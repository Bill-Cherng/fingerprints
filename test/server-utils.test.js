process.env.DB_PATH = ':memory:';

const { test, after } = require('node:test');
const assert = require('node:assert/strict');

const {
    db,
    generateMathCaptcha,
    verifyMathCaptcha,
    calculateMultiFingerprintSimilarity,
    compactComponents,
    compactStoredComponents,
    buildFingerprintData,
    rowToFingerprintData,
    calculateArraySimilarity,
    calculateWebGLSimilarity,
    calculateFingerprintJSSimilarity,
    calculateAudioSimilarity,
    calculateHardwareSimilarity,
    calculateCustomSimilarity
} = require('../server');

function buildFingerprintDataset() {
    return {
        components: {
            canvas: { value: 'canvas-hash' },
            audio: { value: 'audio-fp' },
            fonts: { value: ['Arial', 'Roboto'] },
            hardwareConcurrency: { value: 8 },
            deviceMemory: { value: 16 },
            platform: { value: 'MacIntel' },
            screenResolution: { value: '1920x1080' }
        },
        canvas: 'canvas-hash',
        webgl: {
            renderer: 'ANGLE (Apple, Apple M1, OpenGL 4.1)',
            vendor: 'Apple',
            version: 'WebGL 2.0',
            extensions: ['EXT_color_buffer_float', 'WEBGL_debug_renderer_info']
        },
        audio: { fingerprint: 'audio-fp', sampleRate: 48000 },
        fonts: { available: ['Arial', 'Roboto'] },
        plugins: { names: ['Chrome PDF Viewer'] },
        hardware: { cores: 8, memory: 16, touchPoints: 0 },
        custom: {
            screen: { width: 1920, height: 1080, colorDepth: 24 },
            timezone: 'UTC'
        }
    };
}

test('generateMathCaptcha returns consistent question and answer', () => {
    for (let i = 0; i < 200; i++) {
        assertCaptchaConsistent(generateMathCaptcha());
    }
});

function assertCaptchaConsistent({ question, answer }) {
    assert.match(question, /^\d+ [+\-*] \d+ = \?$/);

    const parts = question.replace(' = ?', '').split(' ');
    const num1 = parseInt(parts[0], 10);
    const operator = parts[1];
    const num2 = parseInt(parts[2], 10);

    let expected;
    switch (operator) {
        case '+':
            expected = num1 + num2;
            break;
        case '-':
            assert.ok(num1 >= num2, 'subtraction question must not produce a negative answer');
            expected = num1 - num2;
            break;
        case '*':
            expected = num1 * num2;
            break;
        default:
            throw new Error('Unexpected operator in CAPTCHA');
    }

    assert.equal(answer, expected);
}

test('verifyMathCaptcha accepts correct answers and rejects incorrect ones', () => {
    assert.equal(verifyMathCaptcha('5', '5'), true);
    assert.equal(verifyMathCaptcha('7', '3'), false);
    assert.equal(verifyMathCaptcha(null, '2'), false);
});

test('calculateMultiFingerprintSimilarity returns 100 for identical fingerprints', () => {
    const baseline = buildFingerprintDataset();
    const result = calculateMultiFingerprintSimilarity(baseline, buildFingerprintDataset());
    assert.equal(result, 100);
});

test('calculateMultiFingerprintSimilarity drops when key traits differ', () => {
    const baseline = buildFingerprintDataset();
    const modified = buildFingerprintDataset();
    modified.canvas = 'different-canvas';
    modified.webgl = {
        renderer: 'Other Renderer',
        vendor: 'Other Vendor',
        version: 'WebGL 1.0',
        extensions: []
    };
    modified.audio = { fingerprint: 'other-fp', sampleRate: 44100 };
    modified.fonts = { available: ['Courier New'] };
    modified.hardware = { cores: 4, memory: 8, touchPoints: 2 };
    modified.custom = {
        screen: { width: 1366, height: 768, colorDepth: 24 },
        timezone: 'Asia/Taipei'
    };

    const result = calculateMultiFingerprintSimilarity(baseline, modified);
    assert.ok(result < 100);
    assert.ok(result >= 0);
});

test('compactComponents hashes large component values and keeps small ones', () => {
    const image = 'data:image/png;base64,' + 'A'.repeat(5000);
    const components = {
        canvas: { value: { image, winding: true }, duration: 12 },
        platform: { value: 'MacIntel', duration: 1 }
    };

    const compact = compactComponents(components);
    assert.match(compact.canvas.value, /^sha256:[0-9a-f]{64}$/);
    assert.equal(compact.canvas.duration, 12);
    assert.deepEqual(compact.platform, components.platform);

    // 相同的值得到相同的雜湊，不同的值得到不同的雜湊，重複壓縮不會改變結果
    assert.equal(compactComponents(structuredClone(components)).canvas.value, compact.canvas.value);
    const changed = compactComponents({ canvas: { value: { image: image + 'B', winding: true } } });
    assert.notEqual(changed.canvas.value, compact.canvas.value);
    assert.deepEqual(compactComponents(compact), compact);

    assert.deepEqual(compactComponents(null), {});
    assert.deepEqual(compactComponents('not-an-object'), {});
});

test('an old row with raw component values still matches the same browser after compaction', () => {
    const components = {
        canvas: { value: { image: 'X'.repeat(4000) } },
        platform: { value: 'MacIntel' }
    };
    // 修改前存入的紀錄：元件值是原始內容
    const oldRow = { components: JSON.stringify(components) };
    const newData = buildFingerprintData({ visitorId: 'same', components });

    assert.match(newData.components.canvas.value, /^sha256:/);
    assert.equal(calculateMultiFingerprintSimilarity(rowToFingerprintData(oldRow), newData), 100);
});

test('compactStoredComponents rewrites existing rows that still hold large values', async () => {
    const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, (err) => (err ? reject(err) : resolve())));
    const get = (sql, params = []) => new Promise((resolve, reject) => db.get(sql, params, (err, row) => (err ? reject(err) : resolve(row))));
    const small = JSON.stringify({ platform: { value: 'Win32' } });
    await run("INSERT INTO fingerprints (visitor_id, components) VALUES ('compact-big', ?)", [JSON.stringify({ canvas: { value: 'Y'.repeat(3000) } })]);
    await run("INSERT INTO fingerprints (visitor_id, components) VALUES ('compact-small', ?)", [small]);

    await new Promise((resolve, reject) => compactStoredComponents(db, (err) => (err ? reject(err) : resolve())));

    const big = await get("SELECT components FROM fingerprints WHERE visitor_id = 'compact-big'");
    assert.match(JSON.parse(big.components).canvas.value, /^sha256:/);
    const untouched = await get("SELECT components FROM fingerprints WHERE visitor_id = 'compact-small'");
    assert.equal(untouched.components, small);
});

test('calculateArraySimilarity handles partial overlap', () => {
    const similarity = calculateArraySimilarity(['A', 'B', 'C'], ['B', 'C', 'D']);
    assert.equal(similarity, (2 / 4) * 100);
});

test('calculateWebGLSimilarity stays within 0-100', () => {
    const extensions = ['EXT_a', 'EXT_b', 'WEBGL_c'];
    const gpu = { renderer: 'NVIDIA', vendor: 'NV', version: 'WebGL 1.0', extensions };

    assert.equal(calculateWebGLSimilarity(gpu, { ...gpu }), 100);

    // renderer/vendor/version 全不同、只有擴展清單相同：只拿到擴展的 0.5 / 3.5
    const other = { renderer: 'Apple M1', vendor: 'Apple', version: 'WebGL 2.0', extensions };
    const similarity = calculateWebGLSimilarity(gpu, other);
    assert.ok(Math.abs(similarity - (0.5 / 3.5) * 100) < 1e-9, `got ${similarity}`);
});

test('two different users sharing only WebGL extensions are not reported as a match', () => {
    const extensions = ['EXT_a', 'EXT_b', 'WEBGL_c'];
    const alice = {
        components: { platform: { value: 'Win32' }, canvas: { value: 'c1' }, fonts: { value: ['Arial'] } },
        canvas: 'hash-1',
        webgl: { renderer: 'NVIDIA', vendor: 'NV', version: 'WebGL 1.0', extensions },
        audio: { fingerprint: 'a1', sampleRate: 48000 },
        fonts: { available: ['Arial', 'Verdana'] },
        hardware: { cores: 16, memory: 32, touchPoints: 0 },
        custom: { screen: { width: 1920, height: 1080, colorDepth: 24 }, timezone: 'Asia/Taipei' }
    };
    const bob = {
        components: { platform: { value: 'MacIntel' }, canvas: { value: 'c2' }, fonts: { value: ['Helvetica'] } },
        canvas: 'hash-2',
        webgl: { renderer: 'Apple M1', vendor: 'Apple', version: 'WebGL 2.0', extensions },
        audio: { fingerprint: 'b2', sampleRate: 44100 },
        fonts: { available: ['Helvetica'] },
        hardware: { cores: 8, memory: 8, touchPoints: 5 },
        custom: { screen: { width: 1440, height: 900, colorDepth: 30 }, timezone: 'Europe/London' }
    };

    const similarity = calculateMultiFingerprintSimilarity(alice, bob);
    assert.ok(similarity < 20, `expected a low similarity, got ${similarity}`);
});

test('fields missing on both sides are not counted as a match', () => {
    // 瀏覽器不支援 deviceMemory 時前端送出 'unknown'；兩邊都 unknown 不代表相同
    assert.equal(
        calculateHardwareSimilarity({ cores: 8, memory: 'unknown', touchPoints: 0 }, { cores: 4, memory: 'unknown', touchPoints: 0 }),
        50
    );
    assert.equal(calculateHardwareSimilarity({ battery: 'x' }, { battery: 'y' }), null);

    assert.equal(calculateCustomSimilarity({ language: 'en' }, { language: 'zh' }), null);
    assert.equal(calculateCustomSimilarity({ timezone: 'Asia/Taipei' }, { timezone: 'Europe/London' }), 0);

    assert.equal(calculateWebGLSimilarity({ pixelData: [1] }, { pixelData: [2] }), null);
});

test('FingerprintJS similarity without important components only uses the general components', () => {
    const similarity = calculateFingerprintJSSimilarity(
        { math: { value: 1 }, vendor: { value: 'a' } },
        { math: { value: 2 }, vendor: { value: 'b' } }
    );
    assert.equal(similarity, 0);
});

test('audio collection failure markers are not treated as matching fingerprints', () => {
    assert.equal(
        calculateAudioSimilarity(
            { fingerprint: 'context_suspended', sampleRate: 48000 },
            { fingerprint: 'context_suspended', sampleRate: 44100 }
        ),
        0
    );
    assert.equal(calculateAudioSimilarity({ fingerprint: 'error' }, { fingerprint: 'error' }), null);
    assert.equal(calculateAudioSimilarity({ fingerprint: 'abc', sampleRate: 48000 }, { fingerprint: 'abc', sampleRate: 48000 }), 100);
});

test('the legacy audio fingerprint "0" is never treated as a match', () => {
    // 舊版前端在音訊播完後才讀取頻譜，每個瀏覽器都得到 '0'；不同裝置不能因此被判定為相同
    assert.equal(
        calculateAudioSimilarity({ fingerprint: '0', sampleRate: 48000 }, { fingerprint: '0', sampleRate: 44100 }),
        0
    );
    assert.equal(calculateAudioSimilarity({ fingerprint: '0' }, { fingerprint: '0' }), null);
    // 舊紀錄與新版前端的結果比較時，只能依採樣率給部分分數
    assert.equal(
        calculateAudioSimilarity({ fingerprint: '0', sampleRate: 48000 }, { fingerprint: '124.04347527516074', sampleRate: 48000 }),
        50
    );
});

test('layers without comparable data are skipped instead of counted as a match', () => {
    // 兩個平台與 canvas 都不同的使用者；硬體資訊兩邊都是瀏覽器不支援的值
    const similarity = calculateMultiFingerprintSimilarity(
        { components: { platform: { value: 'Win32' } }, canvas: 'canvas-a', hardware: { battery: 'not_supported' } },
        { components: { platform: { value: 'MacIntel' } }, canvas: 'canvas-b', hardware: { battery: 'not_supported' } }
    );
    // 硬體層應被略過；若把「都缺少」當成相同，會被灌成約 7.7%
    assert.equal(similarity, 0);
});

after(() => {
    return new Promise((resolve, reject) => {
        db.close((err) => {
            if (err) {
                reject(err);
            } else {
                resolve();
            }
        });
    });
});
