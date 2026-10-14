const assert = require('node:assert/strict');
const { createHmac, generateKeyPairSync, webcrypto } = require('node:crypto');
const { test } = require('node:test');
const { TextDecoder, TextEncoder } = require('node:util');

if (!global.crypto) global.crypto = webcrypto;
if (!global.TextEncoder) global.TextEncoder = TextEncoder;
if (!global.TextDecoder) global.TextDecoder = TextDecoder;
if (!global.atob) global.atob = value => Buffer.from(value, 'base64').toString('binary');
if (!global.btoa) global.btoa = value => Buffer.from(value, 'binary').toString('base64');

let elements = {};
global.window = global;
global.document = {
    readyState: 'loading',
    addEventListener() {},
    getElementById(id) {
        return elements[id] || null;
    }
};

require('../js/jwt-attack-platform.min.js');

const platform = global.jwtAttackPlatform;
const realSignJwtHmac = platform.signJwtHmac;
const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
const publicKeyPkcs1Pem = publicKey.export({ type: 'pkcs1', format: 'pem' });
const publicKeyJwk = publicKey.export({ format: 'jwk' });

function encodeJson(value) {
    return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function makeToken(payload) {
    return `${encodeJson({ alg: 'RS256', typ: 'JWT' })}.${encodeJson(payload)}.signature`;
}

function configureInputs({ payload, modifyPayload, customClaims = '', pem = publicKeyPem, jwks = '' }) {
    elements = {
        'original-token-algo': { value: makeToken(payload) },
        'public-key-algo': { value: pem },
        'jwks-content-algo': { value: jwks },
        'modify-payload-algo': { checked: modifyPayload },
        'custom-claims-algo': { value: customClaims }
    };
}

async function captureMappings() {
    const calls = [];
    const errors = [];

    platform.signJwtHmac = async (header, payload, secret, algorithm) => {
        calls.push({ header, payload, secret: new Uint8Array(secret), algorithm });
        return `generated-token-${calls.length}`;
    };
    platform.showError = message => errors.push(message);
    platform.showPemConversion = () => {};

    await platform.generateAlgoConfusionPayloads();
    return { calls, errors };
}

test('custom claims are merged into every algorithm-confusion payload', async () => {
    configureInputs({
        payload: { sub: 'standard-user', isAdmin: false, user: 'original', retained: true },
        modifyPayload: true,
        customClaims: JSON.stringify({ isAdmin: true, user: 'htb-stdnt' })
    });

    const { calls, errors } = await captureMappings();
    const expectedPayload = {
        sub: 'standard-user',
        isAdmin: true,
        user: 'htb-stdnt',
        retained: true
    };

    assert.deepEqual(errors, []);
    assert.equal(calls.length, 14);
    for (const call of calls) assert.deepEqual(call.payload, expectedPayload);
});

test('disabling payload modification preserves every original claim', async () => {
    const originalPayload = { sub: 'standard-user', isAdmin: false, role: 'reader' };
    configureInputs({
        payload: originalPayload,
        modifyPayload: false,
        customClaims: JSON.stringify({ sub: 'administrator', isAdmin: true })
    });

    const { calls, errors } = await captureMappings();

    assert.deepEqual(errors, []);
    assert.equal(calls.length, 14);
    for (const call of calls) assert.deepEqual(call.payload, originalPayload);
});

test('the administrator default is retained when modification is enabled without custom claims', async () => {
    configureInputs({
        payload: { sub: 'standard-user', isAdmin: false },
        modifyPayload: true
    });

    const { calls, errors } = await captureMappings();

    assert.deepEqual(errors, []);
    assert.equal(calls.length, 14);
    for (const call of calls) {
        assert.deepEqual(call.payload, { sub: 'administrator', isAdmin: false });
    }
});

test('custom claims must be a JSON object', async () => {
    for (const customClaims of ['null', '[]', '"administrator"', '{invalid-json}']) {
        configureInputs({
            payload: { sub: 'standard-user' },
            modifyPayload: true,
            customClaims
        });

        const { calls, errors } = await captureMappings();

        assert.equal(calls.length, 0);
        assert.equal(errors.length, 1);
        assert.match(errors[0], /^Invalid custom claims:/);
    }
});

test('pasted PEM produces distinct with-newline and without-newline secrets', async () => {
    const pemWithoutNewline = publicKeyPem.replace(/[\r\n]+$/, '');
    configureInputs({
        payload: { sub: 'standard-user' },
        modifyPayload: false,
        pem: `${pemWithoutNewline}\n\n`
    });

    const { calls, errors } = await captureMappings();
    const withNewline = Buffer.from(calls[0].secret).toString();
    const withoutNewline = Buffer.from(calls[2].secret).toString();

    assert.deepEqual(errors, []);
    assert.equal(withNewline, `${pemWithoutNewline}\n`);
    assert.equal(withoutNewline, pemWithoutNewline);
    assert.notEqual(withNewline, withoutNewline);
});

test('JWKS-derived PEM produces the same explicit newline variants', async () => {
    configureInputs({
        payload: { sub: 'standard-user' },
        modifyPayload: false,
        pem: '',
        jwks: JSON.stringify({ keys: [publicKeyJwk] })
    });

    const { calls, errors } = await captureMappings();
    const withNewline = Buffer.from(calls[0].secret).toString();
    const withoutNewline = Buffer.from(calls[2].secret).toString();

    assert.deepEqual(errors, []);
    assert.equal(withNewline, `${withoutNewline}\n`);
    assert.equal(withoutNewline.endsWith('\n'), false);
});

test('X.509 SubjectPublicKeyInfo is converted to the exact PKCS#1 RSA key', () => {
    const convertedPem = platform.convertX509ToPKCS1(publicKeyPem.replace(/[\r\n]+$/, ''));

    assert.equal(convertedPem, publicKeyPkcs1Pem);
});

test('newline variants produce independently valid and different HMAC signatures', async () => {
    configureInputs({
        payload: { sub: 'standard-user', isAdmin: false },
        modifyPayload: true,
        customClaims: JSON.stringify({ isAdmin: true })
    });

    const { calls, errors } = await captureMappings();
    assert.deepEqual(errors, []);

    const withNewlineCall = calls[0];
    const withoutNewlineCall = calls[2];
    const withNewlineToken = await realSignJwtHmac.call(
        platform,
        withNewlineCall.header,
        withNewlineCall.payload,
        withNewlineCall.secret,
        withNewlineCall.algorithm
    );
    const withoutNewlineToken = await realSignJwtHmac.call(
        platform,
        withoutNewlineCall.header,
        withoutNewlineCall.payload,
        withoutNewlineCall.secret,
        withoutNewlineCall.algorithm
    );

    for (const [token, secret] of [
        [withNewlineToken, withNewlineCall.secret],
        [withoutNewlineToken, withoutNewlineCall.secret]
    ]) {
        const [header, payload, signature] = token.split('.');
        const expectedSignature = createHmac('sha256', secret)
            .update(`${header}.${payload}`)
            .digest('base64url');
        assert.equal(signature, expectedSignature);
    }

    assert.notEqual(withNewlineToken, withoutNewlineToken);
});

test('all advertised mappings produce real signed tokens with the selected payload', async () => {
    const errors = [];
    configureInputs({
        payload: { sub: 'standard-user', isAdmin: false },
        modifyPayload: true,
        customClaims: JSON.stringify({ isAdmin: true, user: 'htb-stdnt' })
    });
    platform.signJwtHmac = realSignJwtHmac;
    platform.showError = message => errors.push(message);
    platform.showPemConversion = () => {};

    await platform.generateAlgoConfusionPayloads();

    assert.deepEqual(errors, []);
    assert.equal(platform.generatedPayloads.length, 14);
    for (const generated of platform.generatedPayloads) {
        assert.equal(generated.payload.split('.').length, 3);
        assert.deepEqual(platform.decodeJWT(generated.payload).payload, {
            sub: 'standard-user',
            isAdmin: true,
            user: 'htb-stdnt'
        });
    }

    const emptySecretToken = platform.generatedPayloads.find(generated =>
        generated.title.includes('Empty secret')
    ).payload;
    const [header, payload, signature] = emptySecretToken.split('.');
    const expectedEmptyKeySignature = createHmac('sha256', Buffer.alloc(0))
        .update(`${header}.${payload}`)
        .digest('base64url');
    assert.equal(signature, expectedEmptyKeySignature);
});
