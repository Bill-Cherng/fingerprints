process.env.DB_PATH = ':memory:';
process.env.RATE_LIMIT_API_PER_MINUTE = '20';
process.env.RATE_LIMIT_FINGERPRINT_PER_MINUTE = '2';
process.env.RATE_LIMIT_AUTH_PER_15_MIN = '3';
delete process.env.TRUST_PROXY;

// server.js 的 log 輸出會干擾 node --test 與子行程之間的通訊，測試時關閉
console.log = () => {};

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');

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

function request(method, path, { body, headers = {} } = {}) {
    return fetch(baseUrl + path, {
        method,
        headers: { 'Content-Type': 'application/json', ...headers },
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(10000)
    });
}

// 同一個檔案內的測試依序執行，且都來自同一個 IP（127.0.0.1），額度會累計：
// /api 總上限 20 次，前兩個測試合計只用 7 次，因此它們各自只會碰到自己要驗證的那一層限流
test('POST /api/fingerprint is limited per IP and returns a JSON error', async () => {
    const payload = { body: { visitorId: 'v', components: {} } };
    assert.equal((await request('POST', '/api/fingerprint', payload)).status, 200);
    assert.equal((await request('POST', '/api/fingerprint', payload)).status, 200);

    const blocked = await request('POST', '/api/fingerprint', payload);
    assert.equal(blocked.status, 429);
    assert.equal((await blocked.json()).error, '請求過於頻繁，請稍後再試');
    assert.ok(blocked.headers.get('ratelimit-policy'), 'should expose the RateLimit-Policy header');
});

test('login and register share one limit', async () => {
    const statuses = [];
    for (const path of ['/api/auth/login', '/api/auth/register', '/api/auth/login', '/api/auth/register']) {
        const response = await request('POST', path, { body: { username: 'someone', password: 'secret123', captcha: '1' } });
        statuses.push(response.status);
    }
    // 上限 3 次：前 3 次是一般的錯誤回應（驗證碼過期等），第 4 次才被限流
    assert.deepEqual(statuses.map(status => status === 429), [false, false, false, true], statuses.join(', '));
});

test('X-Forwarded-For cannot bypass the per-IP limit unless TRUST_PROXY is set', async () => {
    // 先把 /api 總額度用完
    let status = 200;
    for (let i = 0; i < 20 && status !== 429; i++) {
        status = (await request('GET', '/api/captcha')).status;
    }
    assert.equal(status, 429, 'the general /api limit should be reached');

    const spoofed = await request('GET', '/api/captcha', { headers: { 'X-Forwarded-For': '203.0.113.9' } });
    assert.equal(spoofed.status, 429, 'a spoofed header must not reset the per-IP limit');
});

test('GET /api/stats is exempt so health checks keep working', async () => {
    const stats = await request('GET', '/api/stats');
    assert.equal(stats.status, 200);
});

test('static files are not rate limited', async () => {
    const page = await request('GET', '/app.js');
    assert.equal(page.status, 200);
});
