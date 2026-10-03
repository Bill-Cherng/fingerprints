// 以真實的 Chromium 操作網頁，驗證只有在瀏覽器裡才看得到的前端行為
// 執行：npm run test:e2e（需先執行 npx playwright install chromium）
process.env.DB_PATH = ':memory:';
process.env.RATE_LIMIT_API_PER_MINUTE = '100000';
process.env.RATE_LIMIT_FINGERPRINT_PER_MINUTE = '100000';
process.env.RATE_LIMIT_AUTH_PER_15_MIN = '100000';

// server.js 的大量 stdout 輸出會干擾 node --test 與子行程之間的通訊，測試時關閉
console.log = () => {};

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');

const { app, db } = require('../server');

let server;
let baseUrl;
let browser;

before(async () => {
    await new Promise((resolve) => {
        server = app.listen(0, '127.0.0.1', () => {
            baseUrl = `http://127.0.0.1:${server.address().port}`;
            resolve();
        });
    });
    browser = await chromium.launch();
});

after(async () => {
    await browser?.close();
    await new Promise((resolve) => server.close(() => db.close(() => resolve())));
});

// 每個測試使用獨立的 context（cookie、localStorage 互不影響），並記錄送出的請求與回應
async function openPage(contextOptions = {}) {
    const context = await browser.newContext(contextOptions);
    const page = await context.newPage();
    const requests = [];
    const fingerprintBodies = [];
    const fingerprintResponses = [];

    page.on('request', (request) => {
        requests.push({ method: request.method(), url: request.url() });
        if (request.url().endsWith('/api/fingerprint')) {
            fingerprintBodies.push(JSON.parse(request.postData()));
        }
    });
    page.on('response', async (response) => {
        if (response.url().endsWith('/api/fingerprint')) {
            fingerprintResponses.push({ status: response.status(), body: await response.json() });
        }
    });

    return { context, page, requests, fingerprintBodies, fingerprintResponses };
}

async function waitForReady(page) {
    await page.waitForFunction(
        () => /準備就緒|已登入|初始化失敗/.test(document.getElementById('userStatus').textContent),
        null,
        { timeout: 20000 }
    );
}

async function solveCaptcha(page, type) {
    await page.waitForFunction((t) => /=/.test(document.getElementById(`${t}CaptchaQuestion`).textContent), type);
    const [a, operator, b] = (await page.textContent(`#${type}CaptchaQuestion`)).replace(' = ?', '').split(' ');
    const x = Number(a);
    const y = Number(b);
    return String(operator === '+' ? x + y : operator === '-' ? x - y : x * y);
}

async function collect(page, responses) {
    const count = responses.length;
    await page.click('#collectBtn');
    await page.click('#agreeBtn');
    await page.waitForFunction(() => document.getElementById('collectBtn').disabled === false && document.getElementById('collectBtn').textContent === '開始採集指紋');
    const deadline = Date.now() + 20000;
    while (responses.length <= count && Date.now() < deadline) {
        await page.waitForTimeout(100);
    }
    assert.ok(responses.length > count, 'fingerprint was not submitted');
}

async function registerAndLoginWithEnter(page, username) {
    await page.click('#toggleAuthBtn');
    await page.click('#showRegisterBtn');
    await page.fill('#registerUsername', username);
    await page.fill('#registerPassword', 'secret123');
    await page.fill('#confirmPassword', 'secret123');
    await page.fill('#registerCaptcha', await solveCaptcha(page, 'register'));
    await page.press('#registerCaptcha', 'Enter');

    // 註冊成功後會切回登入表單並預填使用者名稱
    await page.waitForFunction(
        (name) => document.getElementById('loginForm').style.display !== 'none' && document.getElementById('loginUsername').value === name,
        username,
        { timeout: 5000 }
    );
    await page.fill('#loginPassword', 'secret123');
    await page.fill('#loginCaptcha', await solveCaptcha(page, 'login'));
    await page.press('#loginPassword', 'Enter');
    await page.waitForFunction((name) => document.getElementById('currentUserName').textContent === name, username);
}

test('login and register forms submit with Enter, once, and buttons inside do not submit', async () => {
    const { context, page, requests } = await openPage();
    const authPosts = () => requests.filter((r) => r.method === 'POST' && r.url.includes('/api/auth/')).map((r) => new URL(r.url).pathname);
    try {
        await page.goto(baseUrl);
        await page.click('#toggleAuthBtn');

        // 空白表單按 Enter：顯示前端錯誤訊息，不送出請求
        await page.press('#loginUsername', 'Enter');
        await page.waitForSelector('#formErrorMessage', { state: 'visible' });
        assert.deepEqual(authPosts(), []);

        // 切換表單、重新產生驗證碼的按鈕不會送出表單
        await page.click('#showRegisterBtn');
        await page.click('#refreshRegisterCaptcha');
        await page.waitForTimeout(200);
        assert.deepEqual(authPosts(), []);
        assert.equal(await page.textContent('.form-hint'), '可用於登入');

        // 連按兩次 Enter 只送出一次（驗證碼只能用一次，重複送出必定失敗）
        await page.fill('#registerUsername', 'enteruser');
        await page.fill('#registerPassword', 'secret123');
        await page.fill('#confirmPassword', 'secret123');
        await page.fill('#registerCaptcha', await solveCaptcha(page, 'register'));
        await page.press('#registerCaptcha', 'Enter');
        await page.press('#registerCaptcha', 'Enter');
        await page.waitForTimeout(300);
        assert.deepEqual(authPosts(), ['/api/auth/register']);

        await page.waitForFunction(() => document.getElementById('loginUsername').value === 'enteruser', null, { timeout: 5000 });
        await page.fill('#loginPassword', 'secret123');
        await page.fill('#loginCaptcha', await solveCaptcha(page, 'login'));
        await page.press('#loginPassword', 'Enter');
        await page.waitForFunction(() => document.getElementById('currentUserName').textContent === 'enteruser');
        assert.deepEqual(authPosts(), ['/api/auth/register', '/api/auth/login']);
        assert.equal(await page.isVisible('#authModal .modal-content'), false);

        assert.equal(await page.getAttribute('#loginPassword', 'autocomplete'), 'current-password');
        assert.equal(await page.getAttribute('#registerPassword', 'autocomplete'), 'new-password');
        assert.equal(await page.getAttribute('#closeModal', 'aria-label'), '關閉');
    } finally {
        await context.close();
    }
});

test('the same browser gets a stable, non-trivial audio fingerprint and 100% similarity', async () => {
    const { context, page, fingerprintBodies, fingerprintResponses } = await openPage();
    try {
        await page.goto(baseUrl);
        await waitForReady(page);
        await registerAndLoginWithEnter(page, 'stableuser');

        await collect(page, fingerprintResponses);
        await collect(page, fingerprintResponses);

        const [first, second] = fingerprintBodies;
        // 舊版在音訊播完後才讀取，每個瀏覽器都是 '0'
        assert.notEqual(first.audio.fingerprint, '0');
        assert.notEqual(first.audio.fingerprint, 'error');
        assert.equal(second.audio.fingerprint, first.audio.fingerprint);
        assert.match(first.canvas, /^data:image\/png;base64,/);

        assert.equal(fingerprintResponses[1].status, 200);
        assert.equal(fingerprintResponses[1].body.similarity, 100);
        assert.equal(await page.locator('.canvas-preview img').count(), 1);
    } finally {
        await context.close();
    }
});

test('scripts are never loaded from third-party CDNs, even when the local copy fails', async () => {
    const { context, page, requests, fingerprintResponses } = await openPage();
    try {
        await page.goto(baseUrl);
        await waitForReady(page);
        await collect(page, fingerprintResponses);

        // 本地的 FingerprintJS 載入失敗時，舊版會改從外部 CDN 載入未鎖定版本的 script
        await page.route('**/lib/fingerprintjs.min.js', (route) => route.abort());
        await page.reload();
        await page.waitForFunction(() => /初始化失敗/.test(document.getElementById('userStatus').textContent), null, { timeout: 20000 });

        const external = requests.filter((r) => !r.url.startsWith(baseUrl) && !r.url.startsWith('data:'));
        assert.deepEqual(external, []);
    } finally {
        await context.close();
    }
});

test('canvas fingerprint is still sent when FingerprintJS failed to load at startup', async () => {
    const { context, page, fingerprintBodies, fingerprintResponses } = await openPage();
    try {
        let block = true;
        await page.route('**/lib/fingerprintjs.min.js', (route) => (block ? route.abort() : route.continue()));
        await page.goto(baseUrl);
        await page.waitForFunction(() => /初始化失敗/.test(document.getElementById('userStatus').textContent), null, { timeout: 20000 });

        // 之後恢復正常，按採集時會重新載入 FingerprintJS
        block = false;
        await collect(page, fingerprintResponses);

        assert.equal(fingerprintResponses[0].status, 200);
        assert.match(fingerprintBodies[0].canvas, /^data:image\/png;base64,/);
    } finally {
        await context.close();
    }
});

test('a failed CAPTCHA load is shown in red and cleared after a successful reload', async () => {
    const { context, page } = await openPage();
    try {
        let fail = true;
        await page.route('**/api/captcha', (route) => {
            if (fail) {
                fail = false;
                return route.fulfill({ status: 500, body: '{}' });
            }
            return route.continue();
        });
        await page.goto(baseUrl);
        await page.click('#toggleAuthBtn');
        await page.waitForFunction(() => /失敗/.test(document.getElementById('loginCaptchaQuestion').textContent));
        assert.notEqual(await page.evaluate(() => document.getElementById('loginCaptchaQuestion').style.color), '');

        await page.click('#refreshLoginCaptcha');
        await page.waitForFunction(() => /=/.test(document.getElementById('loginCaptchaQuestion').textContent));
        assert.equal(await page.evaluate(() => document.getElementById('loginCaptchaQuestion').style.color), '');
    } finally {
        await context.close();
    }
});

test('unsupported device memory shows N/A and a failed canvas shows no preview', async () => {
    const { context, page, requests, fingerprintBodies, fingerprintResponses } = await openPage();
    try {
        await page.addInitScript(() => {
            Object.defineProperty(Navigator.prototype, 'deviceMemory', { get: () => undefined });
            HTMLCanvasElement.prototype.toDataURL = function () {
                throw new Error('blocked');
            };
        });
        await page.goto(baseUrl);
        await waitForReady(page);
        await collect(page, fingerprintResponses);

        assert.equal(fingerprintBodies[0].canvas, 'error');
        assert.match(await page.textContent('#componentsList'), /記憶體:\s*N\/A/);
        assert.equal(await page.locator('.canvas-preview img').count(), 0);
        assert.ok(!requests.some((r) => r.url.endsWith('/error')), 'should not request /error');
    } finally {
        await context.close();
    }
});

test('the theme follows the system setting until the user toggles it', async () => {
    const { context, page } = await openPage({ colorScheme: 'dark' });
    try {
        await page.goto(baseUrl);
        assert.equal(await page.getAttribute('html', 'data-theme'), 'dark');

        // 沒有手動切換過：系統改成淺色時跟著改變
        await page.emulateMedia({ colorScheme: 'light' });
        await page.waitForFunction(() => document.documentElement.getAttribute('data-theme') === 'light');

        // 手動切換後記住選擇，不再跟隨系統
        await page.click('#themeToggle');
        assert.equal(await page.getAttribute('html', 'data-theme'), 'dark');
        await page.emulateMedia({ colorScheme: 'light' });
        await page.reload();
        assert.equal(await page.getAttribute('html', 'data-theme'), 'dark');
    } finally {
        await context.close();
    }
});
