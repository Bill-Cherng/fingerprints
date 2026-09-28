process.env.DB_PATH = ':memory:';

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const sqlite3 = require('sqlite3');

const { db, SQLiteSessionStore } = require('../server');

after(() => new Promise((resolve) => db.close(() => resolve())));

// 把 callback 風格的 store 方法包成 Promise
function call(store, method, ...args) {
    return new Promise((resolve, reject) => {
        store[method](...args, (err, result) => (err ? reject(err) : resolve(result)));
    });
}

function openDatabase(file) {
    return new Promise((resolve, reject) => {
        const database = new sqlite3.Database(file, (err) => (err ? reject(err) : resolve(database)));
    });
}

function closeDatabase(database) {
    return new Promise((resolve) => database.close(() => resolve()));
}

function sessionData(overrides = {}) {
    return {
        cookie: { expires: new Date(Date.now() + 60 * 60 * 1000).toISOString() },
        userId: 1,
        ...overrides
    };
}

test('set, get and destroy a session', async () => {
    const database = await openDatabase(':memory:');
    const store = new SQLiteSessionStore(database, { cleanupInterval: 0 });

    await call(store, 'set', 'sid-1', sessionData({ username: 'alice' }));
    const loaded = await call(store, 'get', 'sid-1');
    assert.equal(loaded.username, 'alice');

    await call(store, 'destroy', 'sid-1');
    assert.equal(await call(store, 'get', 'sid-1'), null);

    await closeDatabase(database);
});

test('expired sessions are not returned and are removed by clearExpired', async () => {
    const database = await openDatabase(':memory:');
    const store = new SQLiteSessionStore(database, { cleanupInterval: 0 });

    await call(store, 'set', 'expired', sessionData({ cookie: { expires: new Date(Date.now() - 1000).toISOString() } }));
    await call(store, 'set', 'active', sessionData());

    assert.equal(await call(store, 'get', 'expired'), null);

    await new Promise((resolve, reject) => store.clearExpired((err) => (err ? reject(err) : resolve())));
    const rows = await new Promise((resolve, reject) => {
        database.all('SELECT sid FROM sessions ORDER BY sid', (err, result) => (err ? reject(err) : resolve(result)));
    });
    assert.deepEqual(rows.map(row => row.sid), ['active']);

    await closeDatabase(database);
});

test('a corrupted session row is treated as missing instead of failing the request', async () => {
    const database = await openDatabase(':memory:');
    const store = new SQLiteSessionStore(database, { cleanupInterval: 0 });
    await store.ready;

    await new Promise((resolve, reject) => database.run(
        'INSERT INTO sessions (sid, sess, expires) VALUES (?, ?, ?)',
        ['broken', '{not json', Date.now() + 60000],
        (err) => (err ? reject(err) : resolve())
    ));
    assert.equal(await call(store, 'get', 'broken'), null);

    await closeDatabase(database);
});

test('sessions survive a restart when stored in a database file', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'session-store-'));
    const file = path.join(dir, 'sessions.db');

    try {
        const first = await openDatabase(file);
        await call(new SQLiteSessionStore(first, { cleanupInterval: 0 }), 'set', 'persisted', sessionData({ username: 'bob' }));
        await closeDatabase(first);

        // 模擬重新啟動：重新開啟同一個資料庫檔案並建立新的 store
        const second = await openDatabase(file);
        const loaded = await call(new SQLiteSessionStore(second, { cleanupInterval: 0 }), 'get', 'persisted');
        assert.equal(loaded.username, 'bob');
        await closeDatabase(second);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
