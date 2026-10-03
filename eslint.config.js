const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
    {
        // 第三方函式庫（壓縮過的 FingerprintJS）不檢查
        ignores: ['public/lib/**', 'node_modules/**']
    },
    js.configs.recommended,
    {
        // 後端、測試與設定檔：Node.js（CommonJS）
        files: ['server.js', 'eslint.config.js', 'test/**/*.js', 'e2e/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: globals.node
        }
    },
    {
        // 瀏覽器測試中 page.evaluate 等回呼會在瀏覽器裡執行，也會用到瀏覽器的全域變數
        files: ['e2e/**/*.js'],
        languageOptions: {
            globals: { ...globals.node, ...globals.browser }
        }
    },
    {
        // 前端：以 <script> 載入的一般瀏覽器 script
        files: ['public/**/*.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'script',
            globals: {
                ...globals.browser,
                FingerprintJS: 'readonly' // 由 public/lib/fingerprintjs.min.js 提供
            }
        }
    },
    {
        rules: {
            // 以底線開頭的參數（例如 Express 錯誤處理的 next）允許不使用
            'no-unused-vars': ['error', { args: 'after-used', argsIgnorePattern: '^_', caughtErrors: 'none' }]
        }
    }
];
