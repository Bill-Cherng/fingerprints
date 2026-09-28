process.env.DB_PATH = ':memory:';
// 這支測試從同一個 IP 註冊、登入大量帳號；限流行為由 rate-limit.test.js 另外驗證
process.env.RATE_LIMIT_API_PER_MINUTE = '100000';
process.env.RATE_LIMIT_FINGERPRINT_PER_MINUTE = '100000';
process.env.RATE_LIMIT_AUTH_PER_15_MIN = '100000';

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

    async function request(method, path, body) {
        const response = await fetch(baseUrl + path, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(cookie ? { Cookie: cookie } : {})
            },
            body: body ? JSON.stringify(body) : undefined,
            // server 沒有回應時（例如 handler 內未捕捉的例外）讓測試失敗，而不是無限等待
            signal: AbortSignal.timeout(10000)
        });
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) {
            cookie = setCookie.split(';')[0];
        }
        return { status: response.status, body: await response.json() };
    }

    request.cookie = () => cookie;
    request.setCookie = (value) => { cookie = value; };
    return request;
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

function queryAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

test('login issues a new session ID so a pre-planted session cannot be hijacked', async () => {
    const victim = createClient();
    const register = await victim('POST', '/api/auth/register', {
        username: 'dave',
        password: 'secret123',
        captcha: await solvedCaptcha(victim)
    });
    assert.equal(register.status, 200);

    // 攻擊者事先取得並植入的 session ID
    const captcha = await solvedCaptcha(victim);
    const plantedCookie = victim.cookie();

    const login = await victim('POST', '/api/auth/login', { username: 'dave', password: 'secret123', captcha });
    assert.equal(login.status, 200);
    assert.notEqual(victim.cookie(), plantedCookie, 'session ID must change after login');

    const attacker = createClient();
    attacker.setCookie(plantedCookie);
    const me = await attacker('GET', '/api/auth/me');
    assert.equal(me.body.loggedIn, false);

    const victimMe = await victim('GET', '/api/auth/me');
    assert.equal(victimMe.body.loggedIn, true);
});

test('fingerprint listing requires login and only returns the caller\'s own records', async () => {
    const guest = createClient();
    const anonymous = await guest('GET', '/api/fingerprints');
    assert.equal(anonymous.status, 401);

    const erin = createClient();
    await registerAndLogin(erin, 'erin');
    await erin('POST', '/api/fingerprint', buildPayload({ visitorId: 'erin-browser' }));

    const own = await erin('GET', '/api/fingerprints');
    assert.equal(own.status, 200);
    assert.ok(own.body.length > 0);
    assert.ok(own.body.every(row => row.username === 'erin'));
});

test('debug endpoint requires login and hides other users\' fingerprints', async () => {
    const frank = createClient();
    const grace = createClient();
    await registerAndLogin(frank, 'frank');
    await registerAndLogin(grace, 'grace');
    await frank('POST', '/api/fingerprint', buildPayload({ visitorId: 'frank-browser' }));

    const [frankRow] = await queryAll(
        "SELECT f.id FROM fingerprints f JOIN accounts a ON f.linked_user_id = a.id WHERE a.username = 'frank'"
    );

    const anonymous = await createClient()('GET', `/api/debug/fingerprint/${frankRow.id}`);
    assert.equal(anonymous.status, 401);

    const other = await grace('GET', `/api/debug/fingerprint/${frankRow.id}`);
    assert.equal(other.status, 404);

    const own = await frank('GET', `/api/debug/fingerprint/${frankRow.id}`);
    assert.equal(own.status, 200);
    assert.equal(own.body.username, 'frank');
});

test('logout destroys the session and clears the cookie', async () => {
    const henry = createClient();
    await registerAndLogin(henry, 'henry');

    const response = await fetch(`${baseUrl}/api/auth/logout`, { method: 'POST', headers: { Cookie: henry.cookie() } });
    assert.equal(response.status, 200);
    assert.match(response.headers.get('set-cookie') || '', /fingerprint\.sid=;/);

    const me = await henry('GET', '/api/auth/me');
    assert.equal(me.body.loggedIn, false);
});

test('the removed /api/identify endpoint is no longer served', async () => {
    const response = await fetch(`${baseUrl}/api/identify?visitorId=anything`);
    assert.equal(response.status, 404);
});

test('non-string credentials are rejected instead of crashing the server', async () => {
    const request = createClient();

    const numericPassword = await request('POST', '/api/auth/register', {
        username: 'numeric',
        password: 12345678,
        captcha: await solvedCaptcha(request)
    });
    assert.equal(numericPassword.status, 400);

    const objectUsername = await request('POST', '/api/auth/register', {
        username: { length: 5 },
        password: 'secret123',
        captcha: await solvedCaptcha(request)
    });
    assert.equal(objectUsername.status, 400);

    const objectEmail = await request('POST', '/api/auth/register', {
        username: 'objemail',
        email: ['a@b.co'],
        password: 'secret123',
        captcha: await solvedCaptcha(request)
    });
    assert.equal(objectEmail.status, 400);

    const loginNumericPassword = await request('POST', '/api/auth/login', {
        username: 'numeric',
        password: 12345678,
        captcha: await solvedCaptcha(request)
    });
    assert.equal(loginNumericPassword.status, 400);

    const stored = await queryAll("SELECT username FROM accounts WHERE username IN ('numeric', '[object Object]', 'objemail')");
    assert.deepEqual(stored, []);

    // server 仍正常運作
    const stats = await request('GET', '/api/stats');
    assert.equal(stats.status, 200);
});

test('logged-in sessions are stored in the sessions table and removed on logout', async () => {
    const ivy = createClient();
    await registerAndLogin(ivy, 'ivy');

    const sid = decodeURIComponent(ivy.cookie().split('=')[1]).replace(/^s:/, '').split('.')[0];
    const [stored] = await queryAll('SELECT sess FROM sessions WHERE sid = ?', [sid]);
    assert.ok(stored, 'session row should exist after login');
    assert.equal(JSON.parse(stored.sess).username, 'ivy');

    const logout = await ivy('POST', '/api/auth/logout');
    assert.equal(logout.status, 200);
    const remaining = await queryAll('SELECT sid FROM sessions WHERE sid = ?', [sid]);
    assert.deepEqual(remaining, []);
});
