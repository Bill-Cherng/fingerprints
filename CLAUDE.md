# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 常用指令

- **安裝依賴**: `npm install`
- **啟動開發伺服器**: `npm run dev` (使用 nodemon 自動重啟)
- **啟動生產伺服器**: `npm start`
- **執行測試**: `npm test` (使用 Node.js 內建測試執行器)

## 專案架構

本專案是一個使用 FingerprintJS V4 進行瀏覽器指紋採集的測試網站,結合了多層次指紋技術和智慧相似度比對。

### 檔案結構

- **後端**: `server.js` (1100+ 行) - 單一後端檔案,包含所有 API 路由和核心邏輯
  - Express.js + SQLite3 資料庫
  - Session-based 身份驗證 (express-session + bcryptjs)
  - 數學驗證碼系統 (自製 CAPTCHA)
- **前端**: `public/` 目錄
  - `index.html` - 單頁應用介面
  - `app.js` (1400+ 行) - 前端核心邏輯
  - `style.css` - 響應式樣式
  - `lib/` - 第三方函式庫
- **資料庫**: `fingerprints.db` (SQLite3,開發時自動建立)

### 資料庫結構

- **fingerprints 表**: 儲存多重指紋資料
  - 核心欄位: `visitor_id`, `components`, `linked_user_id`
  - 多重指紋欄位: `canvas_fingerprint`, `webgl_fingerprint`, `audio_fingerprint`, `fonts_fingerprint`, `hardware_fingerprint`, `custom_fingerprint`
  - 時間戳記: `created_at`, `last_seen`
- **accounts 表**: 使用者帳號
  - 欄位: `username`, `password_hash`, `created_at`, `last_login`
- **sessions 表**: express-session 的 session 資料
  - 欄位: `sid`, `sess` (JSON), `expires` (毫秒時間戳)

## 核心邏輯與工作流程

### 1. 指紋採集 (前端 app.js)

- 使用 FingerprintJS V4 開源版 (`@fingerprintjs/fingerprintjs@4.6.2`) 採集基礎指紋
- 額外採集 7 種自訂指紋:
  - Canvas 指紋 (繪圖渲染特徵)
  - WebGL 指紋 (GPU/驅動程式特徵)
  - 音訊指紋 (以 OfflineAudioContext 離線運算三角波經壓縮器的輸出,另記錄裝置的實際採樣率)
  - 字體指紋 (已安裝字體列表)
  - 插件指紋 (瀏覽器插件資訊)
  - 硬體指紋 (CPU、記憶體、觸控點)
  - 自訂指紋 (螢幕、時區等)
- 所有指紋資料透過 `POST /api/fingerprint` 發送到後端

### 2. 使用者驗證系統

- **註冊** (`POST /api/auth/register`): bcryptjs 雜湊密碼,需通過數學驗證碼;使用者名稱至少 3 個字元且不可包含 `@` (登入欄位同時接受使用者名稱或 Email,避免名稱冒用別人的 Email)
- **登入** (`POST /api/auth/login`): bcrypt 密碼驗證,需通過數學驗證碼,成功後以 `session.regenerate()` 換發新 session ID;輸入同時符合某帳號的使用者名稱與另一帳號的 Email 時,以 Email 相符者優先
- **Session 管理**: express-session + cookie (24小時有效期),session 以 `SQLiteSessionStore` 存在同一個 SQLite 資料庫的 `sessions` 表,過期資料每 15 分鐘清除
- **CAPTCHA**: 自製數學驗證碼 (加減乘運算),答案儲存在 session 中

### 3. 指紋比對與相似度演算法 (server.js)

**關鍵函數**: `calculateMultiFingerprintSimilarity()` (server.js)

- **多層次加權計算**:
  - FingerprintJS V4 相似度: 40% 權重 (最重要)
  - Canvas 指紋: 20%
  - WebGL 指紋: 15%
  - 音訊指紋: 10%
  - 字體指紋: 10%
  - 硬體指紋: 5%
  - 自訂指紋: 5%
  - 某一層兩邊都沒有可比較的資料時 (欄位缺少、瀏覽器不支援而為 `'unknown'`、音訊採集失敗的 `'context_suspended'`/`'error'`,以及舊版前端一律產生的 `'0'`),該層函式回傳 `null` 並從加權中略過,不會被當成相同

- **FingerprintJS 比對邏輯** (`calculateFingerprintJSSimilarity`, server.js):
  - 重要元件 (canvas, webgl, audio, fonts 等) 權重 70%
  - 一般元件權重 30%;沒有任何重要元件時只看一般元件
  - 易變動元件 (viewport, timezone) 不同時仍給一半分數
  - 自動忽略 session 相關元件 (localStorage, sessionStorage)

- **登入 vs 未登入使用者**:
  - **已登入**: 指紋直接關聯到使用者帳號 (`linked_user_id`),更新時計算相似度
  - **未登入**: 與資料庫所有指紋比對,只保留相似度 ≥ 20% 的結果,返回其中前 5 個最相似用戶 (`GUEST_MATCH_THRESHOLD`)

### 4. API 端點總覽

- **指紋相關**:
  - `POST /api/fingerprint` - 提交指紋 (核心端點,處理登入/未登入邏輯)
  - `GET /api/fingerprints` - 列出目前登入用戶自己的指紋記錄 (需登入)
  - `GET /api/debug/fingerprint/:id` - 查看指紋詳細資料 (需登入，僅限自己的紀錄，其他人的回 404)
- **驗證相關**:
  - `GET /api/captcha` - 生成數學驗證碼
  - `POST /api/auth/register` - 註冊
  - `POST /api/auth/login` - 登入
  - `POST /api/auth/logout` - 登出
  - `GET /api/auth/me` - 取得目前使用者資訊
- **統計相關**:
  - `GET /api/stats` - 總體統計 (指紋數、關聯使用者數、平均信賴度)

## 重要實作細節

### Session 配置

```javascript
session({
  store: sessionStore,  // SQLiteSessionStore,存在同一個 SQLite 資料庫的 sessions 表
  resave: false,  // 未變動的 session 只由 store.touch 更新到期時間
  saveUninitialized: false,  // 寫入過資料的 session 才存檔,不帶 cookie 的請求 (健康檢查等) 不會新增 session
  cookie: {
    secure: 'auto',  // HTTPS 請求才加上 Secure;在代理後方需設定 TRUST_PROXY
    httpOnly: true,
    maxAge: SESSION_MAX_AGE,  // 1 天
    sameSite: 'lax'
  }
})
```

- `express.static` 放在 session 之前,靜態檔案請求不會讀寫 sessions 表

### 指紋相似度閾值

- 顯示相似度: ≥ 20% (未登入使用者比對)
- 高相似度警告: < 90% (已登入使用者指紋變更)

### API 限流 (express-rate-limit,依 IP)

- 所有 `/api`: 每分鐘 100 次 (`GET /api/stats` 除外,供 Render 健康檢查)
- `POST /api/fingerprint`: 每分鐘 10 次 (未登入時會掃描整張指紋表)
- 登入 + 註冊: 每 15 分鐘合計 20 次
- 超過上限回傳 429 與 `{ error: '請求過於頻繁，請稍後再試' }`
- 在代理後方需設定 `TRUST_PROXY` 才能取得真實 IP;測試中以 `RATE_LIMIT_*` 環境變數調整上限

### 錯誤處理

- 資料庫查詢錯誤: 統一返回 500 狀態碼
- 用戶端錯誤 (JSON 格式錯誤 400、內容超過 1MB 上限 413): 依錯誤本身的狀態碼返回,不回報成 500
- CAPTCHA 驗證失敗: 返回 400 + 錯誤訊息
- 欄位型別錯誤 (帳號欄位,以及指紋的 `visitorId`、`version`、`clientId`、`canvas` 不是字串): 返回 400
- 同時註冊相同名稱被 UNIQUE 限制擋下: 返回 400,不回報成 500
- Session 過期: 重新載入 CAPTCHA

## 測試與調試

- 測試目前使用 Node.js 內建測試執行器 (`node --test`)
- 調試端點: `GET /api/debug/fingerprint/:id` 可查看完整指紋資料
- Console 輸出詳細的相似度計算過程 (查看 server.js 終端輸出)

## 部署注意事項

- 環境變數: `PORT` (Render 自動設定), `SESSION_SECRET` (正式環境必填,未設定時拒絕啟動), `TRUST_PROXY` (代理層數,Render 為 1), `RATE_LIMIT_*` (限流上限)
- 資料庫: SQLite 檔案式資料庫,部署時需持久化儲存
- 靜態檔案: 自動從 `public/` 目錄提供服務
- 啟動命令: `npm start` (綁定 0.0.0.0)
- 收到 `SIGINT` / `SIGTERM` (Render 重新部署時送出) 會先關閉資料庫再結束
