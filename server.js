const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// 逐筆的相似度計算、指紋內容等除錯訊息只在 LOG_LEVEL=debug 時輸出：
// 未登入比對時每筆紀錄都會輸出好幾行，正式環境會拖慢回應、塞滿 log，也會留下使用者資料
const DEBUG_LOGGING = process.env.LOG_LEVEL === 'debug';
function debugLog(...args) {
    if (DEBUG_LOGGING) {
        console.log(...args);
    }
}

// Render 等平台會經過代理伺服器，需設定 TRUST_PROXY（代理層數，例如 1）才能取得使用者的真實 IP；
// 本機直連時不要設定，否則使用者可以偽造 X-Forwarded-For 繞過依 IP 的限流
if (process.env.TRUST_PROXY) {
    const proxyHops = Number.parseInt(process.env.TRUST_PROXY, 10);
    if (Number.isInteger(proxyHops) && proxyHops > 0) {
        app.set('trust proxy', proxyHops);
    } else {
        // 設定錯誤時不信任代理；在代理後方會導致所有使用者共用同一個 IP 的限流額度
        console.warn(`TRUST_PROXY 應為正整數（代理層數），目前為 "${process.env.TRUST_PROXY}"，已忽略`);
    }
}

// 簡單的數學 CAPTCHA 驗證
function generateMathCaptcha() {
    let num1 = Math.floor(Math.random() * 10) + 1;
    let num2 = Math.floor(Math.random() * 10) + 1;
    const operators = ['+', '-', '*'];
    const operator = operators[Math.floor(Math.random() * operators.length)];

    // 減法時讓被減數較大，題目與答案才會一致且不為負數
    if (operator === '-' && num1 < num2) {
        [num1, num2] = [num2, num1];
    }
    
    let answer;
    switch (operator) {
        case '+':
            answer = num1 + num2;
            break;
        case '-':
            answer = num1 - num2;
            break;
        case '*':
            answer = num1 * num2;
            break;
    }
    
    return {
        question: `${num1} ${operator} ${num2} = ?`,
        answer: answer
    };
}

// 驗證數學 CAPTCHA 的函數
function verifyMathCaptcha(sessionAnswer, userAnswer) {
    try {
        const sessionNum = parseInt(sessionAnswer);
        const userNum = parseInt(userAnswer);
        return sessionNum === userNum;
    } catch (error) {
        console.error('CAPTCHA 驗證錯誤:', error);
        return false;
    }
}

// 取出並作廢 session 中的 CAPTCHA 答案：每題只能驗證一次，不論對錯都需重新載入，避免暴力猜測
function consumeCaptcha(req, userAnswer) {
    const expected = req.session.captchaAnswer;
    delete req.session.captchaAnswer;

    if (expected === undefined || expected === null) {
        return { valid: false, error: '驗證碼已過期，請重新載入' };
    }

    if (!verifyMathCaptcha(expected, userAnswer)) {
        return { valid: false, error: '驗證碼錯誤，請重新載入' };
    }

    return { valid: true };
}

const SESSION_COOKIE_NAME = 'fingerprint.sid';

// 正式環境必須設定 SESSION_SECRET：原始碼是公開的，內建的預設值等於公開的密鑰
function resolveSessionSecret() {
    if (process.env.SESSION_SECRET) {
        return process.env.SESSION_SECRET;
    }
    if (process.env.NODE_ENV === 'production') {
        throw new Error('正式環境（NODE_ENV=production）必須設定 SESSION_SECRET 環境變數');
    }
    return 'fingerprint-session-secret-key-2025'; // 僅供本機開發與測試
}

// 帳號欄位規則
// 使用者名稱只允許字母（含中文等各國文字）、數字與 _ . -：排除空白、換行、零寬字元等看不見或容易混淆的字元，
// 避免「alice」與「alice 」這類外觀相同的帳號互相冒充；也排除 @，避免名稱與別人的 Email 重疊
const USERNAME_PATTERN = /^[\p{L}\p{N}_.-]{3,30}$/u;
const MAX_EMAIL_LENGTH = 254; // RFC 5321 的 Email 長度上限
const MIN_PASSWORD_LENGTH = 6;
const MAX_PASSWORD_BYTES = 72; // bcrypt 只使用密碼的前 72 bytes，超過的部分會被忽略

// 回傳錯誤訊息；欄位都符合規則時回傳 null
function validateRegistration({ username, email, password }) {
    if (username.includes('@')) {
        return '使用者名稱不可包含 @';
    }
    if (!USERNAME_PATTERN.test(username)) {
        return '使用者名稱需為 3–30 個字母、數字或 _ . -（不可包含空白）';
    }
    if (email && email.length > MAX_EMAIL_LENGTH) {
        return 'Email 過長';
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
        return `密碼至少需要 ${MIN_PASSWORD_LENGTH} 個字元`;
    }
    if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
        return '密碼過長（最多 72 bytes，英數約 72 字、中文約 24 字）';
    }
    return null;
}

// JSON body 可以帶任何型別；帳號欄位必須是字串，否則 bcrypt 會拋出例外，資料庫也會存進 "[object Object]"
function hasInvalidFieldTypes(fields) {
    return Object.values(fields).some(value => value !== undefined && value !== null && typeof value !== 'string');
}

// 資料庫初始化（DB_PATH 可指定其他路徑，測試時使用 :memory:）
// 預設路徑以 server.js 所在目錄為準，不受啟動時的工作目錄影響
const db = new sqlite3.Database(process.env.DB_PATH || path.join(__dirname, 'fingerprints.db'));

const SESSION_MAX_AGE = 24 * 60 * 60 * 1000; // 1 天
const SESSION_CLEANUP_INTERVAL = 15 * 60 * 1000; // 每 15 分鐘清除過期 session

// 以 SQLite 儲存 session，取代預設的 MemoryStore：
// 重新啟動或重新部署後使用者不會被登出，記憶體用量也不會隨 session 數量成長
class SQLiteSessionStore extends session.Store {
    constructor(database, { cleanupInterval = SESSION_CLEANUP_INTERVAL } = {}) {
        super();
        this.db = database;
        // 其他查詢可能在建表完成前就進來，所有操作都先等待資料表建立
        this.ready = new Promise((resolve, reject) => {
            this.db.run(`
                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY,
                    sess TEXT NOT NULL,
                    expires INTEGER NOT NULL
                )
            `, (err) => (err ? reject(err) : resolve()));
        });

        if (cleanupInterval > 0) {
            // unref：不讓清除計時器阻止 process 結束（例如測試跑完時）
            this.cleanupTimer = setInterval(() => this.clearExpired(), cleanupInterval);
            this.cleanupTimer.unref();
        }
    }

    expiresAt(sess) {
        const expires = sess?.cookie?.expires;
        return expires ? new Date(expires).getTime() : Date.now() + SESSION_MAX_AGE;
    }

    run(sql, params, callback) {
        this.ready.then(
            () => this.db.run(sql, params, (err) => callback?.(err || null)),
            (err) => callback?.(err)
        );
    }

    get(sid, callback) {
        this.ready.then(() => {
            this.db.get(
                'SELECT sess FROM sessions WHERE sid = ? AND expires > ?',
                [sid, Date.now()],
                (err, row) => {
                    if (err) return callback(err);
                    if (!row) return callback(null, null);
                    let sess = null;
                    try {
                        sess = JSON.parse(row.sess);
                    } catch (parseErr) {
                        // 內容損毀的 session 視為不存在，讓使用者重新登入
                    }
                    callback(null, sess);
                }
            );
        }, callback);
    }

    set(sid, sess, callback) {
        this.run(
            'INSERT OR REPLACE INTO sessions (sid, sess, expires) VALUES (?, ?, ?)',
            [sid, JSON.stringify(sess), this.expiresAt(sess)],
            callback
        );
    }

    touch(sid, sess, callback) {
        this.run('UPDATE sessions SET expires = ? WHERE sid = ?', [this.expiresAt(sess), sid], callback);
    }

    destroy(sid, callback) {
        this.run('DELETE FROM sessions WHERE sid = ?', [sid], callback);
    }

    clearExpired(callback) {
        this.run('DELETE FROM sessions WHERE expires <= ?', [Date.now()], callback);
    }
}

const sessionStore = new SQLiteSessionStore(db);

// 依 IP 限制 API 請求頻率；上限可用環境變數調整
function envPositiveInt(name, fallback) {
    const value = Number.parseInt(process.env[name], 10);
    return Number.isFinite(value) && value > 0 ? value : fallback;
}

function createRateLimiter({ windowMs, limit, skip }) {
    return rateLimit({
        windowMs,
        limit,
        skip,
        standardHeaders: 'draft-8', // 回傳 RateLimit / RateLimit-Policy 標頭
        legacyHeaders: false,
        // 前端以 JSON 的 error 欄位顯示錯誤訊息
        message: { error: '請求過於頻繁，請稍後再試' }
    });
}

// 所有 API 的基本上限；Render 健康檢查用的 GET /api/stats 不列入，避免健康檢查被擋而被判定服務異常
const apiLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    limit: envPositiveInt('RATE_LIMIT_API_PER_MINUTE', 100),
    skip: (req) => req.method === 'GET' && req.path === '/stats'
});

// 指紋比對：未登入時每次都會與整張指紋表比對，成本最高
const fingerprintLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    limit: envPositiveInt('RATE_LIMIT_FINGERPRINT_PER_MINUTE', 10)
});

// 登入與註冊（合併計算）：防止密碼暴力破解與大量註冊
const authLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    limit: envPositiveInt('RATE_LIMIT_AUTH_PER_15_MIN', 20)
});

// 基本安全標頭，靜態檔案與 API 都套用
app.disable('x-powered-by'); // 不透露使用的框架
app.use((req, res, next) => {
    res.set({
        'X-Content-Type-Options': 'nosniff', // 禁止瀏覽器猜測內容類型
        'X-Frame-Options': 'DENY', // 禁止被嵌入 iframe，防止點擊劫持
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    next();
});

// 中間件
// 靜態檔案不需要 session，放在 session 之前，避免每個 CSS/JS 請求都寫入 session 資料表
app.use(express.static(path.join(__dirname, 'public')));
// 限流放在 session 之前：被擋下的請求不會讀寫 session 資料表
app.use('/api', apiLimiter);
// 啟動後的第一批請求可能早於建表完成（尤其在冷啟動、CPU 忙碌時），等資料庫就緒再處理，否則會查到 "no such table"
app.use('/api', (req, res, next) => {
    dbReady.then(() => next(), next);
});
// 一次指紋提交約 50KB（FingerprintJS 元件含 canvas 影像），預設 100KB 上限太接近，放寬到 1MB
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
    store: sessionStore,
    secret: resolveSessionSecret(),
    // 沒有變動的 session 不重寫整筆資料，只由 store.touch 更新到期時間
    resave: false,
    // 只有寫入過資料（CAPTCHA 答案、登入狀態）的 session 才存檔並發 cookie；
    // 否則健康檢查、爬蟲等不帶 cookie 的請求每次都會新增一筆 session
    saveUninitialized: false,
    cookie: { 
        // 'auto'：HTTPS 請求才加上 Secure 標記；在代理後方需設定 TRUST_PROXY 才能判斷原始請求是否為 HTTPS
        secure: 'auto',
        httpOnly: true, // 防止 XSS 攻擊
        maxAge: SESSION_MAX_AGE, // 1 天，減少 session 存儲時間
        sameSite: 'lax' // CSRF 保護
    },
    name: SESSION_COOKIE_NAME // 自定義 session 名稱
}));

// 多重指紋資料表
// visitor_id 不設 UNIQUE：同一個瀏覽器可能被多個帳號使用，每個帳號各自保有一筆指紋紀錄
const FINGERPRINTS_TABLE_SQL = `
    CREATE TABLE IF NOT EXISTS fingerprints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        visitor_id TEXT,
        confidence_score REAL,
        confidence_comment TEXT,
        version TEXT,
        components TEXT,
        client_id TEXT,
        custom_fingerprint TEXT,
        canvas_fingerprint TEXT,
        webgl_fingerprint TEXT,
        audio_fingerprint TEXT,
        fonts_fingerprint TEXT,
        plugins_fingerprint TEXT,
        hardware_fingerprint TEXT,
        collection_time INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        linked_user_id INTEGER,
        FOREIGN KEY (linked_user_id) REFERENCES accounts(id)
    )
`;

const FINGERPRINTS_COLUMNS = [
    'id', 'visitor_id', 'confidence_score', 'confidence_comment', 'version', 'components',
    'client_id', 'custom_fingerprint', 'canvas_fingerprint', 'webgl_fingerprint',
    'audio_fingerprint', 'fonts_fingerprint', 'plugins_fingerprint', 'hardware_fingerprint',
    'collection_time', 'created_at', 'last_seen', 'linked_user_id'
];

// 舊版資料表的 visitor_id 為 UNIQUE，同一瀏覽器登入第二個帳號時會寫入失敗；偵測到舊結構時重建資料表並保留資料
function migrateFingerprintsTable(database, callback = () => {}) {
    const createIndexes = () => {
        // 每個帳號只保留一筆指紋：先刪掉同一帳號較舊的重複紀錄（同時提交造成的），再建立唯一索引
        database.run(`
            DELETE FROM fingerprints
            WHERE linked_user_id IS NOT NULL AND id NOT IN (
                SELECT id FROM (
                    SELECT id, ROW_NUMBER() OVER (PARTITION BY linked_user_id ORDER BY last_seen DESC, id DESC) AS rank
                    FROM fingerprints
                    WHERE linked_user_id IS NOT NULL
                )
                WHERE rank = 1
            )
        `, function(dedupeErr) {
            if (dedupeErr) {
                console.error('清除重複指紋紀錄失敗:', dedupeErr);
                return callback(dedupeErr);
            }
            if (this.changes > 0) {
                console.log(`已清除 ${this.changes} 筆同一帳號的重複指紋紀錄`);
            }

            database.exec(`
                CREATE INDEX IF NOT EXISTS idx_fingerprints_visitor_id ON fingerprints(visitor_id);
                CREATE INDEX IF NOT EXISTS idx_fingerprints_linked_user_id ON fingerprints(linked_user_id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_fingerprints_one_per_user
                    ON fingerprints(linked_user_id) WHERE linked_user_id IS NOT NULL;
            `, callback);
        });
    };

    database.get("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'fingerprints'", (err, row) => {
        if (err) {
            console.error('檢查指紋資料表結構錯誤:', err);
            return callback(err);
        }

        if (!row || !/visitor_id\s+TEXT\s+UNIQUE/i.test(row.sql)) {
            return createIndexes();
        }

        database.all('PRAGMA table_info(fingerprints)', (infoErr, columns) => {
            if (infoErr) {
                console.error('讀取指紋資料表欄位錯誤:', infoErr);
                return callback(infoErr);
            }

            const sharedColumns = columns
                .map(column => column.name)
                .filter(name => FINGERPRINTS_COLUMNS.includes(name))
                .join(', ');

            database.exec(`
                BEGIN;
                ALTER TABLE fingerprints RENAME TO fingerprints_old;
                ${FINGERPRINTS_TABLE_SQL};
                INSERT INTO fingerprints (${sharedColumns}) SELECT ${sharedColumns} FROM fingerprints_old;
                DROP TABLE fingerprints_old;
                COMMIT;
            `, (migrateErr) => {
                if (migrateErr) {
                    console.error('指紋資料表遷移失敗:', migrateErr);
                    return database.run('ROLLBACK', () => callback(migrateErr));
                }

                console.log('指紋資料表已遷移：移除 visitor_id 的 UNIQUE 限制');
                createIndexes();
            });
        });
    });
}

// 把舊紀錄中的大型元件值換成雜湊；已經壓縮過的紀錄不會再更新
function compactStoredComponents(database, callback = () => {}) {
    database.all('SELECT id, components FROM fingerprints', (err, rows) => {
        if (err) return callback(err);

        const updates = [];
        for (const row of rows) {
            const original = safeJsonParse(row.components, null);
            if (!original) continue;
            const compacted = JSON.stringify(compactComponents(original));
            if (compacted !== JSON.stringify(original)) {
                updates.push([compacted, row.id]);
            }
        }
        if (updates.length === 0) return callback();

        database.serialize(() => {
            database.run('BEGIN');
            const statement = database.prepare('UPDATE fingerprints SET components = ? WHERE id = ?');
            for (const params of updates) statement.run(params);
            statement.finalize();
            database.run('COMMIT', (commitErr) => {
                if (commitErr) return callback(commitErr);
                console.log(`已將 ${updates.length} 筆指紋紀錄的大型元件值換成雜湊`);
                callback();
            });
        });
    });
}

// 建立資料表；dbReady 在建表與資料表遷移都完成後才 resolve
const dbReady = new Promise((resolve, reject) => db.serialize(() => {
    db.run(FINGERPRINTS_TABLE_SQL);

    // 用戶帳號資料表
    db.run(`
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME
        )
    `);

    migrateFingerprintsTable(db, (err) => {
        if (err) return reject(err);
        compactStoredComponents(db, (compactErr) => (compactErr ? reject(compactErr) : resolve()));
    });
}));
// 初始化失敗時，錯誤會在請求進來時由等待 dbReady 的 middleware 交給錯誤處理回報
dbReady.catch((err) => console.error('資料庫初始化失敗:', err));

// 計算多重指紋相似度函數
function calculateMultiFingerprintSimilarity(oldData, newData) {
    const similarities = [];
    const weights = [];
    
    // 1. FingerprintJS V4 相似度 (權重 40% - 提高權重)
    if (oldData.components && newData.components) {
        const fpSimilarity = calculateFingerprintJSSimilarity(oldData.components, newData.components);
        similarities.push(fpSimilarity);
        weights.push(0.4);
        debugLog('FingerprintJS 相似度:', fpSimilarity);
    }
    
    // 2. Canvas 指紋相似度 (權重 20%)
    if (oldData.canvas && newData.canvas && oldData.canvas !== '' && newData.canvas !== '') {
        const canvasSimilarity = calculateCanvasSimilarity(oldData.canvas, newData.canvas);
        similarities.push(canvasSimilarity);
        weights.push(0.2);
        debugLog('Canvas 相似度:', canvasSimilarity);
    }
    
    // 3. WebGL 指紋相似度 (權重 15%)
    if (oldData.webgl && newData.webgl && Object.keys(oldData.webgl).length > 0 && Object.keys(newData.webgl).length > 0) {
        const webglSimilarity = calculateWebGLSimilarity(oldData.webgl, newData.webgl);
        if (webglSimilarity !== null) {
            similarities.push(webglSimilarity);
            weights.push(0.15);
        }
        debugLog('WebGL 相似度:', webglSimilarity);
    }
    
    // 4. 音訊指紋相似度 (權重 10%)
    if (oldData.audio && newData.audio && Object.keys(oldData.audio).length > 0 && Object.keys(newData.audio).length > 0) {
        const audioSimilarity = calculateAudioSimilarity(oldData.audio, newData.audio);
        if (audioSimilarity !== null) {
            similarities.push(audioSimilarity);
            weights.push(0.1);
        }
        debugLog('Audio 相似度:', audioSimilarity);
    }
    
    // 5. 字體指紋相似度 (權重 10%)
    if (oldData.fonts && newData.fonts && Object.keys(oldData.fonts).length > 0 && Object.keys(newData.fonts).length > 0) {
        const fontsSimilarity = calculateFontsSimilarity(oldData.fonts, newData.fonts);
        similarities.push(fontsSimilarity);
        weights.push(0.1);
        debugLog('Fonts 相似度:', fontsSimilarity);
    }
    
    // 6. 硬體指紋相似度 (權重 5%)
    if (oldData.hardware && newData.hardware && Object.keys(oldData.hardware).length > 0 && Object.keys(newData.hardware).length > 0) {
        const hardwareSimilarity = calculateHardwareSimilarity(oldData.hardware, newData.hardware);
        if (hardwareSimilarity !== null) {
            similarities.push(hardwareSimilarity);
            weights.push(0.05);
        }
        debugLog('Hardware 相似度:', hardwareSimilarity);
    }
    
    // 7. 自定義指紋相似度 (權重 5%)
    if (oldData.custom && newData.custom && Object.keys(oldData.custom).length > 0 && Object.keys(newData.custom).length > 0) {
        const customSimilarity = calculateCustomSimilarity(oldData.custom, newData.custom);
        if (customSimilarity !== null) {
            similarities.push(customSimilarity);
            weights.push(0.05);
        }
        debugLog('Custom 相似度:', customSimilarity);
    }
    
    if (similarities.length === 0) {
        return 0;
    }
    
    // 計算加權平均相似度
    let weightedSum = 0;
    let totalWeight = 0;
    
    for (let i = 0; i < similarities.length; i++) {
        weightedSum += similarities[i] * weights[i];
        totalWeight += weights[i];
    }
    
    const finalSimilarity = Math.round((weightedSum / totalWeight) * 10) / 10;
    
    // 調試信息
    debugLog('相似度計算調試:', {
        similarities,
        weights,
        weightedSum,
        totalWeight,
        finalSimilarity,
        availableTypes: similarities.length
    });
    
    return Math.min(100, Math.max(0, finalSimilarity));
}

// 計算 FingerprintJS V4 相似度
function calculateFingerprintJSSimilarity(oldComponents, newComponents) {
    const oldKeys = Object.keys(oldComponents);
    const newKeys = Object.keys(newComponents);
    
    if (oldKeys.length === 0 || newKeys.length === 0) {
        return 0;
    }
    
    let totalComponents = 0;
    let matchingComponents = 0;
    let importantMatches = 0;
    let importantTotal = 0;
    
    // 重要的指紋元件（權重較高）
    const importantComponents = [
        'canvas', 'webgl', 'audio', 'fonts', 'screenResolution', 
        'hardwareConcurrency', 'deviceMemory', 'platform'
    ];
    
    // 容易變化的元件（權重較低或忽略）
    const volatileComponents = ['viewport', 'timezone'];
    
    // 會因為瀏覽器重啟而變化的元件（完全忽略）
    const sessionBasedComponents = ['domBlockers', 'sessionStorage', 'localStorage', 'indexedDB'];
    
    const allKeys = new Set([...oldKeys, ...newKeys]);
    
    for (const key of allKeys) {
        const oldValue = oldComponents[key];
        const newValue = newComponents[key];
        
        // 跳過錯誤的元件和會話相關元件
        if ((oldValue && oldValue.error) || (newValue && newValue.error) || sessionBasedComponents.includes(key)) {
            continue;
        }
        
        totalComponents++;
        const isImportant = importantComponents.includes(key);
        const isVolatile = volatileComponents.includes(key);
        
        if (isImportant) {
            importantTotal++;
        }
        
        // 比較值（忽略 duration 差異）
        if (oldValue && newValue) {
            const oldVal = JSON.stringify(oldValue.value);
            const newVal = JSON.stringify(newValue.value);
            
            if (oldVal === newVal) {
                matchingComponents++;
                if (isImportant) {
                    importantMatches++;
                }
            } else if (isVolatile) {
                // 對於容易變化的元件，給予部分分數
                matchingComponents += 0.5;
            }
        }
    }
    
    if (totalComponents === 0) {
        return 0;
    }
    
    // 計算基本相似度
    const basicSimilarity = (matchingComponents / totalComponents) * 100;
    
    // 沒有任何重要元件可比對時只看一般元件；原本預設重要元件 100%，會讓完全不同的元件也得到 70%
    if (importantTotal === 0) {
        return Math.round(basicSimilarity * 10) / 10;
    }

    // 綜合計算（重要元件權重 70%，一般元件權重 30%）
    const importantSimilarity = (importantMatches / importantTotal) * 100;
    const finalSimilarity = (importantSimilarity * 0.7) + (basicSimilarity * 0.3);
    
    return Math.round(finalSimilarity * 10) / 10;
}

// 瀏覽器不支援或未採集到的值；前端在不支援時會送出 'unknown'
function isUnknownValue(value) {
    return value === undefined || value === null || value === '' || value === 'unknown';
}

// 逐欄比對 [舊值, 新值]；兩邊都沒有值的欄位不列入計算，避免把「都缺少」當成「相同」
function compareKnownFields(pairs) {
    let matches = 0;
    let total = 0;
    for (const [oldValue, newValue] of pairs) {
        if (isUnknownValue(oldValue) && isUnknownValue(newValue)) continue;
        total++;
        if (oldValue === newValue) matches++;
    }
    return { matches, total };
}

// 計算 Canvas 相似度
function calculateCanvasSimilarity(oldCanvas, newCanvas) {
    if (oldCanvas === newCanvas) {
        return 100;
    }
    
    // 簡單的雜湊比較
    const oldHash = hashString(oldCanvas);
    const newHash = hashString(newCanvas);
    
    if (oldHash === newHash) {
        return 100;
    }
    
    // 如果完全不同，返回 0
    return 0;
}

// 計算 WebGL 相似度
function calculateWebGLSimilarity(oldWebGL, newWebGL) {
    if (!oldWebGL || !newWebGL) return 0;
    
    // 比較基本資訊
    let { matches, total } = compareKnownFields([
        [oldWebGL.renderer, newWebGL.renderer],
        [oldWebGL.vendor, newWebGL.vendor],
        [oldWebGL.version, newWebGL.version]
    ]);
    
    // 比較擴展（權重 0.5）；calculateArraySimilarity 回傳 0-100 的百分比，需先換算成 0-1 再與上面的計分相加
    const oldExtensions = oldWebGL.extensions || [];
    const newExtensions = newWebGL.extensions || [];
    if (oldExtensions.length > 0 || newExtensions.length > 0) {
        const extensionSimilarity = calculateArraySimilarity(oldExtensions, newExtensions);
        matches += (extensionSimilarity / 100) * 0.5;
        total += 0.5;
    }
    
    // 沒有任何可比較的資料時回傳 null，由呼叫端略過這一層
    return total > 0 ? (matches / total) * 100 : null;
}

// 'context_suspended'、'error' 是採集失敗的標記；'0' 是舊版前端的結果（音訊播完才讀取，每個瀏覽器都是 0），
// 資料庫中的舊紀錄都是 '0'，一律視為無法比較
const AUDIO_FINGERPRINT_SENTINELS = ['context_suspended', 'error', '0'];

// 計算音訊相似度
function calculateAudioSimilarity(oldAudio, newAudio) {
    if (!oldAudio || !newAudio) return 0;
    
    // 這些標記不是真正的指紋，不能拿來判定相同
    const oldFingerprint = AUDIO_FINGERPRINT_SENTINELS.includes(oldAudio.fingerprint) ? undefined : oldAudio.fingerprint;
    const newFingerprint = AUDIO_FINGERPRINT_SENTINELS.includes(newAudio.fingerprint) ? undefined : newAudio.fingerprint;
    
    if (!isUnknownValue(oldFingerprint) && oldFingerprint === newFingerprint) {
        return 100;
    }
    
    if (isUnknownValue(oldAudio.sampleRate) && isUnknownValue(newAudio.sampleRate)) {
        // 指紋與採樣率都無法比較
        return isUnknownValue(oldFingerprint) && isUnknownValue(newFingerprint) ? null : 0;
    }
    
    if (oldAudio.sampleRate === newAudio.sampleRate) {
        return 50; // 部分匹配
    }
    
    return 0;
}

// 計算字體相似度
function calculateFontsSimilarity(oldFonts, newFonts) {
    if (!oldFonts || !newFonts) return 0;
    
    const oldAvailable = oldFonts.available || [];
    const newAvailable = newFonts.available || [];
    
    return calculateArraySimilarity(oldAvailable, newAvailable);
}

// 計算硬體相似度
function calculateHardwareSimilarity(oldHardware, newHardware) {
    if (!oldHardware || !newHardware) return 0;
    
    const { matches, total } = compareKnownFields([
        [oldHardware.cores, newHardware.cores],
        [oldHardware.memory, newHardware.memory],
        [oldHardware.touchPoints, newHardware.touchPoints]
    ]);
    
    return total > 0 ? (matches / total) * 100 : null;
}

// 計算自定義指紋相似度
function calculateCustomSimilarity(oldCustom, newCustom) {
    if (!oldCustom || !newCustom) return 0;
    
    const oldScreen = oldCustom.screen || {};
    const newScreen = newCustom.screen || {};
    
    // 比較螢幕資訊與時區
    const { matches, total } = compareKnownFields([
        [oldScreen.width, newScreen.width],
        [oldScreen.height, newScreen.height],
        [oldScreen.colorDepth, newScreen.colorDepth],
        [oldCustom.timezone, newCustom.timezone]
    ]);
    
    return total > 0 ? (matches / total) * 100 : null;
}

// 計算陣列相似度
function calculateArraySimilarity(oldArray, newArray) {
    if (!Array.isArray(oldArray) || !Array.isArray(newArray)) return 0;
    
    const oldSet = new Set(oldArray);
    const newSet = new Set(newArray);
    
    const intersection = new Set([...oldSet].filter(x => newSet.has(x)));
    const union = new Set([...oldSet, ...newSet]);
    
    return union.size > 0 ? (intersection.size / union.size) * 100 : 0;
}

// 雜湊字串
function hashString(str) {
    let hash = 0;
    if (str.length === 0) return hash.toString(16);
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // 轉換為 32 位整數
    }
    return hash.toString(16);
}

// 中間件：檢查是否已登入
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: '未登入' });
    }
}

// API 路由：生成數學 CAPTCHA
app.get('/api/captcha', (req, res) => {
    try {
        const captcha = generateMathCaptcha();
        
        // 將答案存儲在 session 中
        req.session.captchaAnswer = captcha.answer;
        
        debugLog('生成 CAPTCHA:', { question: captcha.question });
        
        // 確保 session 被保存
        req.session.save((err) => {
            if (err) {
                console.error('Session 保存錯誤:', err);
                // 即使 session 保存失敗，也返回 CAPTCHA 問題
                // 這樣用戶至少可以看到問題，雖然驗證可能失敗
                return res.json({
                    question: captcha.question,
                    timestamp: Date.now(),
                    warning: 'Session 保存失敗，驗證可能不穩定'
                });
            }
            
            debugLog('CAPTCHA session 保存成功');
            
            res.json({
                question: captcha.question,
                timestamp: Date.now()
            });
        });
    } catch (error) {
        console.error('CAPTCHA 生成錯誤:', error);
        res.status(500).json({ error: '無法生成驗證碼' });
    }
});

// API 路由：用戶註冊
app.post('/api/auth/register', authLimiter, async (req, res) => {
    const { username, email, password, captcha } = req.body;

    // 驗證輸入
    if (hasInvalidFieldTypes({ username, email, password })) {
        return res.status(400).json({ error: '欄位格式不正確' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: '請填寫所有欄位' });
    }

    // 驗證 email 格式（如果提供）；長度先檢查，避免對超長字串跑正規表示式
    if (email && email.length <= MAX_EMAIL_LENGTH) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Email 格式不正確' });
        }
    }
    
    // 驗證數學 CAPTCHA
    if (!captcha) {
        return res.status(400).json({ error: '請完成驗證碼' });
    }
    
    const captchaResult = consumeCaptcha(req, captcha);
    if (!captchaResult.valid) {
        debugLog('註冊 CAPTCHA 驗證失敗:', captchaResult.error);
        return res.status(400).json({ error: captchaResult.error });
    }
    
    const validationError = validateRegistration({ username, email, password });
    if (validationError) {
        return res.status(400).json({ error: validationError });
    }
    
    try {
        // 檢查使用者名稱是否已存在
        db.get('SELECT id FROM accounts WHERE username = ?', [username], async (err, existingUser) => {
            if (err) {
                console.error('檢查用戶錯誤:', err);
                return res.status(500).json({ error: '系統錯誤' });
            }

            if (existingUser) {
                return res.status(400).json({ error: '使用者名稱已存在' });
            }

            // 如果提供了 email，檢查是否已存在
            if (email) {
                db.get('SELECT id FROM accounts WHERE email = ?', [email], async (emailErr, existingEmail) => {
                    if (emailErr) {
                        console.error('檢查 email 錯誤:', emailErr);
                        return res.status(500).json({ error: '系統錯誤' });
                    }

                    if (existingEmail) {
                        return res.status(400).json({ error: 'Email 已被使用' });
                    }

                    // 繼續註冊流程
                    await createUser();
                });
            } else {
                await createUser();
            }

            // 在 db callback 裡執行，外層 try/catch 接不到這裡的例外；自行捕捉，避免 unhandled rejection 讓整個 process 結束
            async function createUser() {
                let hashedPassword;
                try {
                    // 加密密碼
                    const saltRounds = 10;
                    hashedPassword = await bcrypt.hash(password, saltRounds);
                } catch (hashErr) {
                    console.error('密碼加密錯誤:', hashErr);
                    return res.status(500).json({ error: '註冊失敗' });
                }

                // 建立新用戶
                db.run(
                    'INSERT INTO accounts (username, email, password_hash) VALUES (?, ?, ?)',
                    [username, email || null, hashedPassword],
                    function(insertErr) {
                        if (insertErr) {
                            // 同時註冊相同名稱時，前面的重複檢查都會通過，由 UNIQUE 限制擋下，屬於用戶端錯誤
                            if (insertErr.code === 'SQLITE_CONSTRAINT') {
                                const error = /accounts\.email/.test(insertErr.message) ? 'Email 已被使用' : '使用者名稱已存在';
                                return res.status(400).json({ error });
                            }
                            console.error('建立用戶錯誤:', insertErr);
                            return res.status(500).json({ error: '註冊失敗' });
                        }

                        console.log('新用戶註冊成功:', { id: this.lastID, username });
                        res.json({
                            success: true,
                            message: '註冊成功！',
                            userId: this.lastID
                        });
                    }
                );
            }
        });
    } catch (error) {
        console.error('註冊錯誤:', error);
        res.status(500).json({ error: '註冊失敗' });
    }
});

// API 路由：用戶登入
app.post('/api/auth/login', authLimiter, async (req, res) => {
    const { username, password, captcha, rememberMe } = req.body;

    if (hasInvalidFieldTypes({ username, password })) {
        return res.status(400).json({ error: '欄位格式不正確' });
    }

    if (!username || !password) {
        return res.status(400).json({ error: '請輸入使用者名稱/Email 和密碼' });
    }

    // 驗證數學 CAPTCHA
    if (!captcha) {
        return res.status(400).json({ error: '請完成驗證碼' });
    }

    const captchaResult = consumeCaptcha(req, captcha);
    if (!captchaResult.valid) {
        debugLog('登入 CAPTCHA 驗證失敗:', captchaResult.error);
        return res.status(400).json({ error: captchaResult.error });
    }

    // 查找用戶（支援 username 或 email）
    // 舊資料可能有使用者名稱等於別人 Email 的帳號，同時符合時以 Email 相符的帳號優先
    const query = 'SELECT * FROM accounts WHERE username = ? OR email = ? ORDER BY CASE WHEN email = ? THEN 0 ELSE 1 END LIMIT 1';
    db.get(query, [username, username, username], async (err, user) => {
        if (err) {
            console.error('登入查詢錯誤:', err);
            return res.status(500).json({ error: '登入失敗' });
        }

        if (!user) {
            return res.status(401).json({ error: '使用者名稱/Email 或密碼錯誤' });
        }

        try {
            // 驗證密碼
            const passwordMatch = await bcrypt.compare(password, user.password_hash);

            if (!passwordMatch) {
                return res.status(401).json({ error: '使用者名稱/Email 或密碼錯誤' });
            }

            // 登入成功後換發新的 session ID，避免 session fixation：攻擊者預先植入的 session ID 不會變成已登入狀態
            req.session.regenerate((regenerateErr) => {
                if (regenerateErr) {
                    console.error('Session 重新產生錯誤:', regenerateErr);
                    return res.status(500).json({ error: '登入失敗' });
                }

                req.session.userId = user.id;
                req.session.username = user.username;

                // 如果勾選「記住我」，延長 cookie 有效期到 30 天
                if (rememberMe) {
                    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000; // 30 天
                    debugLog('啟用「記住我」功能，session 有效期延長至 30 天');
                } else {
                    req.session.cookie.maxAge = 24 * 60 * 60 * 1000; // 1 天（預設）
                }

                req.session.save((saveErr) => {
                    if (saveErr) {
                        console.error('Session 保存錯誤:', saveErr);
                        return res.status(500).json({ error: '登入失敗' });
                    }

                    // 更新最後登入時間
                    db.run('UPDATE accounts SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

                    console.log('用戶登入成功:', { id: user.id, username: user.username, rememberMe: !!rememberMe });

                    res.json({
                        success: true,
                        message: '登入成功！',
                        user: {
                            id: user.id,
                            username: user.username,
                            email: user.email
                        }
                    });
                });
            });
        } catch (error) {
            console.error('密碼驗證錯誤:', error);
            res.status(500).json({ error: '登入失敗' });
        }
    });
});

// API 路由：用戶登出
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('登出錯誤:', err);
            return res.status(500).json({ error: '登出失敗' });
        }
        
        res.clearCookie(SESSION_COOKIE_NAME);
        res.json({ success: true, message: '登出成功！' });
    });
});

// API 路由：獲取當前用戶資訊
app.get('/api/auth/me', (req, res) => {
    if (!req.session.userId) {
        return res.json({ loggedIn: false });
    }
    
    db.get('SELECT id, username, created_at, last_login FROM accounts WHERE id = ?', [req.session.userId], (err, user) => {
        if (err || !user) {
            return res.json({ loggedIn: false });
        }
        
        res.json({
            loggedIn: true,
            user: {
                id: user.id,
                username: user.username,
                createdAt: user.created_at,
                lastLogin: user.last_login
            }
        });
    });
});

// API 路由：處理多重指紋資料
app.post('/api/fingerprint', fingerprintLimiter, (req, res) => {
    const { 
        visitorId, 
        confidence, 
        version, 
        components, 
        clientId,
        custom,
        canvas,
        webgl,
        audio,
        fonts,
        plugins,
        hardware,
        collectionTime,
        timestamp 
    } = req.body;

    // 這些欄位會直接存入資料庫或做雜湊，型別不對時回 400，避免存進 "[object Object]" 或在雜湊時拋出例外
    if (hasInvalidFieldTypes({ visitorId, version, clientId, canvas })) {
        return res.status(400).json({ error: '欄位格式不正確' });
    }

    if (!visitorId) {
        return res.status(400).json({ error: '缺少訪客 ID' });
    }

    debugLog('收到多重指紋資料:', {
        visitorId,
        confidence: confidence?.score,
        version,
        componentsCount: Object.keys(components || {}).length,
        clientId,
        hasCustom: !!custom,
        hasCanvas: !!canvas,
        hasWebGL: !!webgl,
        hasAudio: !!audio,
        hasFonts: !!fonts,
        hasPlugins: !!plugins,
        hasHardware: !!hardware,
        collectionTime,
        isLoggedIn: !!req.session.userId,
        userId: req.session.userId
    });
    
    // 調試：顯示所有元件名稱
    debugLog('採集的元件:', Object.keys(components || {}).sort().join(', '));
    
    const fingerprintData = buildFingerprintData(req.body);

    // **新邏輯：區分登入和未登入用戶**
    if (req.session.userId) {
        // **已登入用戶：將指紋關聯到該用戶帳號**
        handleLoggedInUserFingerprint(req, res, fingerprintData);
    } else {
        // **未登入用戶：比對現有指紋並顯示相似度**
        handleGuestUserFingerprint(req, res, fingerprintData);
    }
});

function safeJsonParse(text, fallback) {
    if (!text) return fallback;
    try {
        return JSON.parse(text);
    } catch (error) {
        console.error('JSON 解析錯誤:', error.message);
        return fallback;
    }
}

// FingerprintJS 元件中超過這個長度（JSON 字元數）的值，儲存時改存雜湊
const COMPONENT_VALUE_HASH_THRESHOLD = 1024;
const HASHED_VALUE_PREFIX = 'sha256:';

// 比對只看元件值是否完全相同，不需要原始內容；canvas 等元件含整張影像（每筆約 40KB），
// 未登入比對時要解析整張指紋表，換成雜湊後資料量與比對時間都能大幅下降
function compactComponents(components) {
    if (!components || typeof components !== 'object' || Array.isArray(components)) {
        return {};
    }
    const compact = {};
    for (const [key, component] of Object.entries(components)) {
        const json = component && typeof component === 'object' ? JSON.stringify(component.value) : undefined;
        if (json !== undefined && json.length > COMPONENT_VALUE_HASH_THRESHOLD) {
            const hash = crypto.createHash('sha256').update(json).digest('hex');
            compact[key] = { ...component, value: HASHED_VALUE_PREFIX + hash };
        } else {
            compact[key] = component;
        }
    }
    return compact;
}

// 採集失敗的指紋（帶有 error 欄位）視為沒有資料，避免兩筆錯誤結果被當成相同
function usableFingerprint(value) {
    if (!value || typeof value !== 'object' || value.error) return {};
    return value;
}

// 將請求中的指紋資料正規化成比對與儲存用的結構
// canvas 只保留雜湊，不把整段 dataURL 存進資料庫
function buildFingerprintData(body) {
    const { visitorId, confidence, version, components, clientId, custom, canvas, webgl, audio, fonts, plugins, hardware, collectionTime } = body;

    return {
        visitorId,
        confidence,
        version,
        clientId,
        collectionTime,
        components: compactComponents(components),
        canvas: canvas && canvas !== 'error' ? hashString(canvas) : '',
        webgl: usableFingerprint(webgl),
        audio: usableFingerprint(audio),
        fonts: usableFingerprint(fonts),
        plugins: usableFingerprint(plugins),
        hardware: usableFingerprint(hardware),
        custom: usableFingerprint(custom)
    };
}

// 將資料庫紀錄還原成比對用的結構
function rowToFingerprintData(row) {
    return {
        // 舊紀錄可能還存著原始的大型元件值，比對前同樣換成雜湊，才能和新資料一致
        components: compactComponents(safeJsonParse(row.components, {})),
        canvas: row.canvas_fingerprint || '',
        webgl: safeJsonParse(row.webgl_fingerprint, {}),
        audio: safeJsonParse(row.audio_fingerprint, {}),
        fonts: safeJsonParse(row.fonts_fingerprint, {}),
        plugins: safeJsonParse(row.plugins_fingerprint, {}),
        hardware: safeJsonParse(row.hardware_fingerprint, {}),
        custom: safeJsonParse(row.custom_fingerprint, {})
    };
}

// 寫入資料庫的欄位值，順序對應 FINGERPRINT_WRITE_COLUMNS
const FINGERPRINT_WRITE_COLUMNS = [
    'visitor_id', 'confidence_score', 'confidence_comment', 'version', 'components', 'client_id',
    'custom_fingerprint', 'canvas_fingerprint', 'webgl_fingerprint', 'audio_fingerprint',
    'fonts_fingerprint', 'plugins_fingerprint', 'hardware_fingerprint', 'collection_time'
];

function fingerprintWriteValues(data) {
    return [
        data.visitorId,
        data.confidence?.score || 0,
        data.confidence?.comment || '',
        data.version || '',
        JSON.stringify(data.components),
        data.clientId || null,
        JSON.stringify(data.custom),
        data.canvas,
        JSON.stringify(data.webgl),
        JSON.stringify(data.audio),
        JSON.stringify(data.fonts),
        JSON.stringify(data.plugins),
        JSON.stringify(data.hardware),
        Number.isFinite(data.collectionTime) ? data.collectionTime : null
    ];
}

// 處理登入用戶的指紋
function handleLoggedInUserFingerprint(req, res, newData) {
    const userId = req.session.userId;
    
    // 檢查該用戶是否已有指紋記錄
    db.get(
        'SELECT * FROM fingerprints WHERE linked_user_id = ? ORDER BY last_seen DESC LIMIT 1',
        [userId],
        (err, existingRecord) => {
            if (err) {
                console.error('查詢用戶指紋錯誤:', err);
                return res.status(500).json({ error: '資料庫查詢失敗' });
            }
            
            if (existingRecord) {
                // 更新現有指紋前，先與舊的多重指紋比對
                const similarity = calculateMultiFingerprintSimilarity(rowToFingerprintData(existingRecord), newData);
                const setClause = FINGERPRINT_WRITE_COLUMNS.map(column => `${column} = ?`).join(', ');
                
                db.run(
                    `UPDATE fingerprints SET ${setClause}, last_seen = CURRENT_TIMESTAMP WHERE id = ?`,
                    [...fingerprintWriteValues(newData), existingRecord.id],
                    function(updateErr) {
                        if (updateErr) {
                            console.error('更新用戶指紋錯誤:', updateErr);
                            return res.status(500).json({ error: '更新失敗' });
                        }
                        
                        debugLog(`更新登入用戶 ${userId} 的指紋, 相似度: ${similarity.toFixed(1)}%`);
                        
                        // 查詢用戶名稱
                        db.get('SELECT username FROM accounts WHERE id = ?', [userId], (userErr, user) => {
                            res.json({
                                isNewUser: false,
                                userId: existingRecord.id,
                                similarity: similarity,
                                message: `已登入用戶 ${user?.username || userId} 的指紋已更新`,
                                fingerprintChanged: similarity < 90,
                                isLoggedIn: true
                            });
                        });
                    }
                );
            } else {
                // 新增指紋記錄
                // 同一帳號同時送出多個請求時，前面的查詢都會是「沒有紀錄」；
                // 由唯一索引 idx_fingerprints_one_per_user 擋下重複，改為更新同一筆，不會產生第二筆紀錄
                const placeholders = FINGERPRINT_WRITE_COLUMNS.map(() => '?').join(', ');
                const updateClause = FINGERPRINT_WRITE_COLUMNS.map(column => `${column} = excluded.${column}`).join(', ');
                db.get(
                    `INSERT INTO fingerprints (${FINGERPRINT_WRITE_COLUMNS.join(', ')}, linked_user_id) VALUES (${placeholders}, ?)
                     ON CONFLICT(linked_user_id) WHERE linked_user_id IS NOT NULL
                     DO UPDATE SET ${updateClause}, last_seen = CURRENT_TIMESTAMP
                     RETURNING id`,
                    [...fingerprintWriteValues(newData), userId],
                    (insertErr, inserted) => {
                        if (insertErr) {
                            console.error('新增用戶指紋錯誤:', insertErr);
                            return res.status(500).json({ error: '新增失敗' });
                        }
                        
                        debugLog(`新增登入用戶 ${userId} 的指紋記錄`);
                        
                        // 查詢用戶名稱
                        db.get('SELECT username FROM accounts WHERE id = ?', [userId], (userErr, user) => {
                            res.json({
                                isNewUser: true,
                                userId: inserted.id,
                                message: `已登入用戶 ${user?.username || userId} 的指紋已存儲`,
                                isLoggedIn: true
                            });
                        });
                    }
                );
            }
        }
    );
}

// 未登入比對時，相似度達到這個門檻（%）才列出
const GUEST_MATCH_THRESHOLD = 20;

// 處理訪客的指紋(未登入)
function handleGuestUserFingerprint(req, res, newData) {

    // 比對現有所有指紋，找出相似度最高的前5個
    db.all(
        'SELECT f.*, a.username FROM fingerprints f LEFT JOIN accounts a ON f.linked_user_id = a.id',
        (err, allUsers) => {
            if (err) {
                console.error('查詢所有指紋錯誤:', err);
                return res.status(500).json({ error: '資料庫查詢失敗' });
            }

            // 計算與所有用戶的多重指紋相似度並排序；同一帳號只保留相似度最高的一筆，避免同一人在結果中出現多次
            const bestByAccount = new Map();
            
            for (const user of allUsers) {
                const similarity = calculateMultiFingerprintSimilarity(rowToFingerprintData(user), newData);
                
                debugLog(`與指紋 ID ${user.id} (用戶: ${user.username || '未登入'}) 多重指紋相似度: ${similarity.toFixed(1)}%`);
                
                if (similarity > 0) { // 只記錄有相似度的結果
                    const accountKey = user.linked_user_id ? `user-${user.linked_user_id}` : `fingerprint-${user.id}`;
                    const best = bestByAccount.get(accountKey);
                    if (!best || similarity > best.similarity) {
                        bestByAccount.set(accountKey, {
                            id: user.linked_user_id || user.id,
                            username: user.username || `ID-${user.linked_user_id || user.id}`,
                            fingerprintId: user.id,
                            similarity: similarity
                        });
                    }
                }
            }
            const similarityResults = [...bestByAccount.values()];

            // 只保留相似度 20% 以上的結果，按相似度降序排序，取前5個
            const top5Matches = similarityResults
                .filter(match => match.similarity >= GUEST_MATCH_THRESHOLD)
                .sort((a, b) => b.similarity - a.similarity)
                .slice(0, 5);

            // **關鍵：返回前5個最相似的用戶**
            if (top5Matches.length > 0) {
                debugLog(`找到 ${top5Matches.length} 個相似用戶，最高相似度: ${top5Matches[0].similarity.toFixed(1)}%`);
                
                // 生成相似度列表訊息
                const similarityList = top5Matches.map((match, index) => 
                    `${index + 1}. 用戶${match.username}: ${match.similarity.toFixed(1)}%`
                ).join('\n');
                
                // 不存儲訪客指紋，只返回比對結果
                res.json({
                    isNewUser: true, // 訪客是新的，但找到相似的
                    similarity: top5Matches[0].similarity,
                    topMatches: top5Matches,
                    message: `找到 ${top5Matches.length} 個相似用戶：\n\n${similarityList}`,
                    isGuest: true
                });
            } else {
                // 沒有找到相似的指紋
                debugLog('沒有找到相似的指紋');
                
                res.json({
                    isNewUser: true,
                    similarity: 0,
                    topMatches: [],
                    message: '完全新的訪客，沒有找到相似的指紋',
                    isGuest: true
                });
            }
        }
    );
}

// API 路由：獲取目前登入用戶的指紋記錄（不開放查詢其他人的紀錄）
app.get('/api/fingerprints', isAuthenticated, (req, res) => {
    db.all(
        'SELECT f.id, f.visitor_id, f.confidence_score, f.version, f.created_at, f.last_seen, f.linked_user_id, a.username FROM fingerprints f LEFT JOIN accounts a ON f.linked_user_id = a.id WHERE f.linked_user_id = ? ORDER BY f.last_seen DESC',
        [req.session.userId],
        (err, rows) => {
            if (err) {
                console.error('查詢錯誤:', err);
                return res.status(500).json({ error: '查詢失敗' });
            }

            res.json(rows);
        }
    );
});

// API 路由：獲取指紋詳細資料（用於調試，只能查看自己帳號的指紋）
app.get('/api/debug/fingerprint/:id', isAuthenticated, (req, res) => {
    const fingerprintId = req.params.id;
    
    // 不屬於自己的紀錄一律回 404，不透露該 ID 是否存在
    db.get(
        'SELECT f.*, a.username FROM fingerprints f LEFT JOIN accounts a ON f.linked_user_id = a.id WHERE f.id = ? AND f.linked_user_id = ?',
        [fingerprintId, req.session.userId],
        (err, row) => {
            if (err) {
                console.error('查詢錯誤:', err);
                return res.status(500).json({ error: '查詢失敗' });
            }
            
            if (!row) {
                return res.status(404).json({ error: '找不到指紋記錄' });
            }
            
            const components = safeJsonParse(row.components, {});
            const componentNames = Object.keys(components).sort();
            
            res.json({
                ...row,
                components: components,
                componentNames: componentNames,
                componentCount: componentNames.length
            });
        }
    );
});

// API 路由：獲取統計資料
app.get('/api/stats', (req, res) => {
    db.get(
        'SELECT COUNT(*) as total_fingerprints, AVG(confidence_score) as avg_confidence, COUNT(DISTINCT linked_user_id) as total_linked_users FROM fingerprints',
        (err, row) => {
            if (err) {
                console.error('統計查詢錯誤:', err);
                return res.status(500).json({ error: '統計查詢失敗' });
            }

            res.json({
                totalFingerprints: row.total_fingerprints,
                totalLinkedUsers: row.total_linked_users,
                averageConfidence: row.avg_confidence ? (row.avg_confidence * 100).toFixed(1) : 0
            });
        }
    );
});

// 首頁路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 錯誤處理中間件
// body-parser 等中介軟體的錯誤會帶有 4xx 狀態碼（格式錯誤 400、內容過大 413），屬於用戶端錯誤，不應回報成 500
const CLIENT_ERROR_MESSAGES = {
    400: '請求格式不正確',
    413: '請求內容過大'
};

app.use((err, req, res, next) => {
    const status = err.status || err.statusCode;
    if (status >= 400 && status < 500) {
        return res.status(status).json({ error: CLIENT_ERROR_MESSAGES[status] || '請求無法處理' });
    }

    console.error('伺服器錯誤:', err);
    res.status(500).json({ error: '內部伺服器錯誤' });
});

// 匯出供測試使用的物件
module.exports = {
    app,
    db,
    SQLiteSessionStore,
    generateMathCaptcha,
    verifyMathCaptcha,
    calculateMultiFingerprintSimilarity,
    calculateFingerprintJSSimilarity,
    calculateCanvasSimilarity,
    calculateWebGLSimilarity,
    calculateAudioSimilarity,
    calculateFontsSimilarity,
    calculateHardwareSimilarity,
    calculateCustomSimilarity,
    calculateArraySimilarity,
    hashString,
    consumeCaptcha,
    validateRegistration,
    migrateFingerprintsTable,
    compactComponents,
    compactStoredComponents,
    buildFingerprintData,
    rowToFingerprintData
};

// 啟動伺服器
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`伺服器運行在 http://0.0.0.0:${PORT}`);
        console.log('FingerprintJS V4 指紋採集測試網站已啟動');
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
}

// 優雅關閉：本機按 Ctrl+C 送出 SIGINT，Render 等平台重新部署時送出 SIGTERM
function shutdown() {
    console.log('\n正在關閉伺服器...');
    db.close((err) => {
        if (err) {
            console.error('關閉資料庫時發生錯誤:', err);
        } else {
            console.log('資料庫已關閉');
        }
        process.exit(0);
    });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
