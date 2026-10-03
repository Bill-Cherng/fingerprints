process.env.DB_PATH = ':memory:';
process.env.RATE_LIMIT_API_PER_MINUTE = '100000';
process.env.RATE_LIMIT_FINGERPRINT_PER_MINUTE = '100000';
process.env.RATE_LIMIT_AUTH_PER_15_MIN = '100000';

// server.js 的大量 stdout 輸出會干擾 node --test 與子行程之間的通訊，測試時關閉
console.log = () => {};

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { spawn } = require('child_process');

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

function createClient() {
    let cookie = null;
    return async function request(method, urlPath, body) {
        const response = await fetch(baseUrl + urlPath, {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...(cookie ? { Cookie: cookie } : {})
            },
            body: body ? JSON.stringify(body) : undefined,
            signal: AbortSignal.timeout(10000)
        });
        const setCookie = response.headers.get('set-cookie');
        if (setCookie) {
            cookie = setCookie.split(';')[0];
        }
        return { status: response.status, body: await response.json() };
    };
}

async function solvedCaptcha(request) {
    const { body } = await request('GET', '/api/captcha');
    const [num1, operator, num2] = body.question.replace(' = ?', '').split(' ');
    const a = Number(num1);
    const b = Number(num2);
    return String(operator === '+' ? a + b : operator === '-' ? a - b : a * b);
}

async function register(request, fields) {
    return request('POST', '/api/auth/register', { password: 'secret123', ...fields, captcha: await solvedCaptcha(request) });
}

async function login(request, username, password = 'secret123') {
    return request('POST', '/api/auth/login', { username, password, captcha: await solvedCaptcha(request) });
}

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, (err) => (err ? reject(err) : resolve()));
    });
}

function queryAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => (err ? reject(err) : resolve(rows)));
    });
}

test('usernames containing @ are rejected so they cannot shadow another user\'s email', async () => {
    const request = createClient();
    const result = await register(request, { username: 'someone@example.com' });

    assert.equal(result.status, 400);
    assert.match(result.body.error, /@/);
    assert.deepEqual(await queryAll("SELECT id FROM accounts WHERE username = 'someone@example.com'"), []);
});

test('logging in by email picks the email owner even if an older account uses that email as its username', async () => {
    // 修正前註冊的舊帳號：使用者名稱剛好等於別人的 Email，且 id 較小，查詢時會先被取到
    await run("INSERT INTO accounts (username, password_hash) VALUES ('owner@example.com', 'not-a-real-hash')");

    const owner = createClient();
    const registered = await register(owner, { username: 'owner', email: 'owner@example.com' });
    assert.equal(registered.status, 200, JSON.stringify(registered.body));

    const result = await login(owner, 'owner@example.com');
    assert.equal(result.status, 200, JSON.stringify(result.body));
    assert.equal(result.body.user.username, 'owner');
});

test('guest comparison only lists matches at or above 20%', async () => {
    const close = createClient();
    const far = createClient();
    await register(close, { username: 'close' });
    await register(far, { username: 'far' });
    await login(close, 'close');
    await login(far, 'far');

    const payload = {
        visitorId: 'close-browser',
        components: { canvas: { value: 1 }, other: { value: 1 } },
        hardware: { cores: 4, memory: 8, touchPoints: 0 }
    };
    assert.equal((await close('POST', '/api/fingerprint', payload)).status, 200);
    // 與 payload 只有一個一般元件相同，相似度約 13%
    assert.equal((await far('POST', '/api/fingerprint', {
        visitorId: 'far-browser',
        components: { canvas: { value: 9 }, other: { value: 1 } },
        hardware: { cores: 2, memory: 4, touchPoints: 5 }
    })).status, 200);

    const guest = createClient();
    const result = await guest('POST', '/api/fingerprint', payload);

    assert.equal(result.status, 200);
    assert.deepEqual(result.body.topMatches.map(match => match.username), ['close']);
    assert.ok(result.body.topMatches.every(match => match.similarity >= 20));
});

test('fingerprint fields with the wrong type are rejected with 400', async () => {
    const request = createClient();
    await register(request, { username: 'typed' });
    await login(request, 'typed');

    const arrayCanvas = await request('POST', '/api/fingerprint', { visitorId: 'typed-browser', canvas: ['a'] });
    assert.equal(arrayCanvas.status, 400);

    const objectVisitorId = await request('POST', '/api/fingerprint', { visitorId: { a: 1 } });
    assert.equal(objectVisitorId.status, 400);

    const numericClientId = await request('POST', '/api/fingerprint', { visitorId: 'typed-browser', clientId: 42 });
    assert.equal(numericClientId.status, 400);

    const [account] = await queryAll("SELECT id FROM accounts WHERE username = 'typed'");
    assert.deepEqual(await queryAll('SELECT id FROM fingerprints WHERE linked_user_id = ?', [account.id]), []);
});

test('simultaneous registrations of the same username return 400, not 500', async () => {
    const first = createClient();
    const second = createClient();
    const [firstCaptcha, secondCaptcha] = await Promise.all([solvedCaptcha(first), solvedCaptcha(second)]);

    // 兩個請求同時送出，重複檢查都會在任何一筆寫入前通過，只能由資料庫的 UNIQUE 限制擋下
    const results = await Promise.all([
        first('POST', '/api/auth/register', { username: 'racer', password: 'secret123', captcha: firstCaptcha }),
        second('POST', '/api/auth/register', { username: 'racer', password: 'secret123', captcha: secondCaptcha })
    ]);

    assert.deepEqual(results.map(result => result.status).sort(), [200, 400]);
    assert.equal(results.find(result => result.status === 400).body.error, '使用者名稱已存在');
});

test('the server closes the database and exits cleanly on SIGTERM', async () => {
    const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
        env: { ...process.env, PORT: '0', DB_PATH: ':memory:', NODE_ENV: 'test' },
        stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('server did not start')), 10000);
        child.stdout.on('data', (chunk) => {
            stdout += chunk;
            if (stdout.includes('伺服器運行在')) {
                clearTimeout(timer);
                resolve();
            }
        });
        child.on('exit', () => reject(new Error(`server exited early: ${stdout}`)));
    });

    const exited = new Promise((resolve) => child.on('exit', (code, signal) => resolve({ code, signal })));
    child.kill('SIGTERM');
    const { code, signal } = await exited;

    assert.equal(signal, null, 'process should handle SIGTERM instead of being killed by it');
    assert.equal(code, 0);
    assert.match(stdout, /資料庫已關閉/);
});

test('registration rejects usernames that are too long or only differ by spaces or invisible characters', async () => {
    const accepted = createClient();
    assert.equal((await register(accepted, { username: 'lookalike' })).status, 200);

    // 外觀與 lookalike 相同、或超出長度的名稱
    for (const username of ['lookalike ', ' lookalike', 'look​alike', 'look\nalike', 'u'.repeat(31), 'u'.repeat(50000)]) {
        const request = createClient();
        const result = await register(request, { username });
        assert.equal(result.status, 400, JSON.stringify(username.slice(0, 40)));
        assert.match(result.body.error, /3–30/);
    }

    // 中文與 _ . - 是允許的
    const chinese = createClient();
    assert.equal((await register(chinese, { username: '王小明_test.01-a' })).status, 200);

    const stored = await queryAll("SELECT username FROM accounts WHERE username LIKE '%lookalike%' OR length(username) > 30");
    assert.deepEqual(stored.map((row) => row.username), ['lookalike']);
});

test('registration rejects overly long emails and passwords bcrypt would truncate', async () => {
    const longEmail = createClient();
    const emailResult = await register(longEmail, { username: 'longemail', email: `${'a'.repeat(250)}@x.com` });
    assert.equal(emailResult.status, 400);
    assert.match(emailResult.body.error, /Email 過長/);

    // bcrypt 只使用前 72 bytes：72 個英數字可以，73 個不行；中文一個字 3 bytes，25 個字就超過
    const exact = createClient();
    assert.equal((await register(exact, { username: 'pw72', password: 'p'.repeat(72) })).status, 200);
    for (const [username, password] of [['pw73', 'p'.repeat(73)], ['pwzh', '密'.repeat(25)]]) {
        const request = createClient();
        const result = await register(request, { username, password });
        assert.equal(result.status, 400, username);
        assert.match(result.body.error, /密碼過長/);
    }
});

test('simultaneous first submissions from one account keep a single fingerprint record', async () => {
    const request = createClient();
    await register(request, { username: 'concurrent' });
    await login(request, 'concurrent');

    const payload = {
        visitorId: 'concurrent-browser',
        components: { platform: { value: 'Win32' } },
        hardware: { cores: 4, memory: 8, touchPoints: 0 }
    };
    const results = await Promise.all([1, 2, 3].map(() => request('POST', '/api/fingerprint', payload)));
    assert.deepEqual(results.map((result) => result.status), [200, 200, 200]);

    const rows = await queryAll(
        "SELECT f.id FROM fingerprints f JOIN accounts a ON a.id = f.linked_user_id WHERE a.username = 'concurrent'"
    );
    assert.equal(rows.length, 1);
    // 每個回應指向同一筆紀錄
    assert.deepEqual([...new Set(results.map((result) => result.body.userId))], [rows[0].id]);

    // 訪客比對時，同一個人只出現一次
    const guest = createClient();
    const guestResult = await guest('POST', '/api/fingerprint', payload);
    const names = guestResult.body.topMatches.map((match) => match.username);
    assert.equal(names.filter((name) => name === 'concurrent').length, 1);
});

test('migrateFingerprintsTable removes duplicate records per account, keeping the most recent one', async () => {
    const sqlite3 = require('sqlite3');
    const { migrateFingerprintsTable } = require('../server');
    const legacy = new sqlite3.Database(':memory:');
    const exec = (sql) => new Promise((resolve, reject) => legacy.exec(sql, (err) => (err ? reject(err) : resolve())));
    const all = (sql) => new Promise((resolve, reject) => legacy.all(sql, (err, rows) => (err ? reject(err) : resolve(rows))));

    await exec(`
        CREATE TABLE fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_id TEXT,
            components TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            linked_user_id INTEGER
        );
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('old', '2026-01-01 00:00:00', 7);
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('newest', '2026-03-01 00:00:00', 7);
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('middle', '2026-02-01 00:00:00', 7);
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('other-user', '2026-01-01 00:00:00', 8);
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('guest-a', '2026-01-01 00:00:00', NULL);
        INSERT INTO fingerprints (visitor_id, last_seen, linked_user_id) VALUES ('guest-b', '2026-01-01 00:00:00', NULL);
    `);

    await new Promise((resolve, reject) => migrateFingerprintsTable(legacy, (err) => (err ? reject(err) : resolve())));

    const rows = await all('SELECT visitor_id FROM fingerprints ORDER BY id');
    assert.deepEqual(rows.map((row) => row.visitor_id), ['newest', 'other-user', 'guest-a', 'guest-b']);

    // 之後不能再為同一帳號新增第二筆
    await assert.rejects(exec("INSERT INTO fingerprints (visitor_id, linked_user_id) VALUES ('again', 7)"), /UNIQUE/);

    await new Promise((resolve) => legacy.close(resolve));
});
