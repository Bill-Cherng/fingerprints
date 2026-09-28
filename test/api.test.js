process.env.DB_PATH = ':memory:';

// server.js 的大量 stdout 輸出會干擾 node --test 與子行程之間的通訊，測試時關閉
console.log = () => {};

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const sqlite3 = require('sqlite3');

const { app, db, migrateFingerprintsTable } = require('../server');

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

// 每個 client 以 cookie 維持自己的 session
function createClient() {
    let cookie = null;

    return async function request(method, path, body) {
        const response = await fetch(baseUrl + path, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(cookie ? { Cookie: cookie } : {})
            },
            body: body ? JSON.stringify(body) : undefined
        });
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) {
            cookie = setCookie.split(';')[0];
        }
        return { status: response.status, body: await response.json() };
    };
}

function solveCaptcha(question) {
    const [num1, operator, num2] = question.replace(' = ?', '').split(' ');
    const a = Number(num1);
    const b = Number(num2);
    return String(operator === '+' ? a + b : operator === '-' ? a - b : a * b);
}

async function solvedCaptcha(request) {
    const { body } = await request('GET', '/api/captcha');
    return solveCaptcha(body.question);
}

async function registerAndLogin(request, username) {
    const register = await request('POST', '/api/auth/register', {
        username,
        password: 'secret123',
        captcha: await solvedCaptcha(request)
    });
    assert.equal(register.status, 200, JSON.stringify(register.body));

    const login = await request('POST', '/api/auth/login', {
        username,
        password: 'secret123',
        captcha: await solvedCaptcha(request)
    });
    assert.equal(login.status, 200, JSON.stringify(login.body));
}

function buildPayload(overrides = {}) {
    return {
        visitorId: 'shared-browser',
        confidence: { score: 0.9 },
        version: '4.6.2',
        components: { platform: { value: 'MacIntel' }, hardwareConcurrency: { value: 8 } },
        canvas: 'data:image/png;base64,AAAA',
        webgl: { renderer: 'GPU', vendor: 'Vendor', version: 'WebGL 1.0', extensions: ['A', 'B'] },
        audio: { fingerprint: 'abc', sampleRate: 48000 },
        fonts: { available: ['Arial', 'Verdana'] },
        plugins: { browser: [] },
        hardware: { cores: 8, memory: 16, touchPoints: 0 },
        custom: { screen: { width: 1920, height: 1080, colorDepth: 24 }, timezone: 'Asia/Taipei' },
        collectionTime: 120,
        ...overrides
    };
}

test('a CAPTCHA can only be attempted once, even after a wrong answer', async () => {
    const request = createClient();
    const answer = await solvedCaptcha(request);
    const wrong = String(Number(answer) + 1);

    const first = await request('POST', '/api/auth/register', { username: 'brute', password: 'secret123', captcha: wrong });
    assert.equal(first.status, 400);

    const second = await request('POST', '/api/auth/register', { username: 'brute', password: 'secret123', captcha: answer });
    assert.equal(second.status, 400);
    assert.match(second.body.error, /過期/);
});

test('two accounts can store fingerprints from the same browser', async () => {
    const alice = createClient();
    const bob = createClient();
    await registerAndLogin(alice, 'alice');
    await registerAndLogin(bob, 'bob');

    const first = await alice('POST', '/api/fingerprint', buildPayload());
    const second = await bob('POST', '/api/fingerprint', buildPayload());

    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(second.status, 200, JSON.stringify(second.body));
});

test('all fingerprint layers are persisted and used for comparison', async () => {
    const carol = createClient();
    await registerAndLogin(carol, 'carol');
    await carol('POST', '/api/fingerprint', buildPayload({ visitorId: 'carol-browser' }));

    const row = await new Promise((resolve, reject) => {
        db.get("SELECT * FROM fingerprints WHERE visitor_id = 'carol-browser'", (err, result) => (err ? reject(err) : resolve(result)));
    });
    assert.ok(row.canvas_fingerprint);
    assert.notEqual(row.canvas_fingerprint, 'data:image/png;base64,AAAA', 'canvas is stored as a hash');
    assert.equal(JSON.parse(row.webgl_fingerprint).renderer, 'GPU');
    assert.equal(JSON.parse(row.hardware_fingerprint).cores, 8);

    // components 完全相同，只有其他指紋層改變時，相似度仍應下降
    const changed = await carol('POST', '/api/fingerprint', buildPayload({
        visitorId: 'carol-browser',
        canvas: 'data:image/png;base64,BBBB',
        webgl: { renderer: 'Other GPU', vendor: 'Other', version: 'WebGL 2.0', extensions: [] }
    }));
    assert.equal(changed.status, 200);
    assert.ok(changed.body.similarity < 100, `expected similarity below 100, got ${changed.body.similarity}`);
});

test('guest comparison returns matches against stored accounts', async () => {
    const guest = createClient();
    const result = await guest('POST', '/api/fingerprint', buildPayload({ visitorId: 'guest-browser' }));

    assert.equal(result.status, 200);
    assert.ok(result.body.topMatches.length > 0);
    assert.ok(result.body.topMatches.every(match => typeof match.username === 'string'));
});

test('migrateFingerprintsTable removes the UNIQUE constraint and keeps existing rows', async () => {
    const legacy = new sqlite3.Database(':memory:');
    await new Promise((resolve, reject) => legacy.exec(`
        CREATE TABLE fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_id TEXT UNIQUE,
            components TEXT,
            linked_user_id INTEGER
        );
        INSERT INTO fingerprints (visitor_id, components, linked_user_id) VALUES ('v1', '{}', 1);
    `, (err) => (err ? reject(err) : resolve())));

    await new Promise((resolve, reject) => migrateFingerprintsTable(legacy, (err) => (err ? reject(err) : resolve())));

    const insertDuplicate = () => new Promise((resolve, reject) => {
        legacy.run("INSERT INTO fingerprints (visitor_id, components, linked_user_id) VALUES ('v1', '{}', 2)", (err) => (err ? reject(err) : resolve()));
    });
    await insertDuplicate();

    const rows = await new Promise((resolve, reject) => {
        legacy.all('SELECT visitor_id, linked_user_id, canvas_fingerprint FROM fingerprints ORDER BY id', (err, result) => (err ? reject(err) : resolve(result)));
    });
    assert.deepEqual(rows.map(row => row.linked_user_id), [1, 2]);
    assert.equal(rows[0].canvas_fingerprint, null);

    await new Promise((resolve) => legacy.close(resolve));
});
