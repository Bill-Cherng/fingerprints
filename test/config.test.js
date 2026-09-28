process.env.DB_PATH = ':memory:';
process.env.TRUST_PROXY = '1';
process.env.RATE_LIMIT_API_PER_MINUTE = '100000';
process.env.RATE_LIMIT_FINGERPRINT_PER_MINUTE = '100000';

// server.js 的 log 輸出會干擾 node --test 與子行程之間的通訊，測試時關閉
console.log = () => {};
console.error = () => {};

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { app, db } = require('../server');

let server;
let baseUrl;

before(() => new Promise((resolve) => {
    server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${server.address().port}`;
        resolve();
    });
}));

after(() => new Promise((resolve) => {
    server.close(() => db.close(() => resolve()));
}));

function post(pathname, rawBody) {
    return fetch(baseUrl + pathname, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: rawBody,
        signal: AbortSignal.timeout(10000)
    });
}

test('malformed JSON returns 400 instead of 500', async () => {
    const response = await post('/api/auth/login', '{not json');
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, '請求格式不正確');
});

test('a fingerprint payload larger than 100KB is accepted', async () => {
    const body = JSON.stringify({ visitorId: 'large', components: {}, canvas: 'x'.repeat(150 * 1024) });
    const response = await post('/api/fingerprint', body);
    assert.equal(response.status, 200);
});

test('a body over the 1MB limit returns 413 instead of 500', async () => {
    const body = JSON.stringify({ visitorId: 'huge', canvas: 'x'.repeat(1100 * 1024) });
    const response = await post('/api/fingerprint', body);
    assert.equal(response.status, 413);
    assert.equal((await response.json()).error, '請求內容過大');
});

test('the session cookie is Secure only for HTTPS requests behind the proxy', async () => {
    const overHttps = await fetch(`${baseUrl}/api/captcha`, { headers: { 'X-Forwarded-Proto': 'https' } });
    assert.match(overHttps.headers.get('set-cookie') || '', /;\s*Secure/i);

    const overHttp = await fetch(`${baseUrl}/api/captcha`);
    assert.doesNotMatch(overHttp.headers.get('set-cookie') || '', /;\s*Secure/i);
});

// 在獨立的子行程載入 server.js，驗證啟動時的設定檢查
function loadServer(env) {
    const serverPath = path.join(__dirname, '..', 'server.js');
    return spawnSync(process.execPath, ['-e', `require(${JSON.stringify(serverPath)}); process.exit(0);`], {
        env: { PATH: process.env.PATH, DB_PATH: ':memory:', ...env },
        encoding: 'utf8',
        timeout: 20000
    });
}

test('production refuses to start without SESSION_SECRET', () => {
    const result = loadServer({ NODE_ENV: 'production' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /SESSION_SECRET/);
});

test('production starts when SESSION_SECRET is set', () => {
    const result = loadServer({ NODE_ENV: 'production', SESSION_SECRET: 'test-secret' });
    assert.equal(result.status, 0, result.stderr);
});
