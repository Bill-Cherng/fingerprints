# FingerprintJS V4 指紋採集測試網站

一個使用 FingerprintJS V4 進行瀏覽器指紋採集的測試網站，支援用戶識別和相似度比對。

## 功能特色

- 使用 FingerprintJS V4 進行高精度瀏覽器指紋採集
- 支援用戶註冊和登入系統
- 智慧指紋相似度比對演算法
- 即時視窗大小監控
- 註冊與登入需通過數學驗證碼（自製 CAPTCHA）
- 響應式設計

## 本地開發

### 安裝套件
```bash
npm install
```

### 啟動開發伺服器
```bash
npm run dev
```

### 啟動生產伺服器
```bash
npm start
```

### 執行測試
```bash
npm test
```

## 部署到 Render

### 1. 準備專案
確保你的專案已經準備好部署：
- 所有檔案都已提交到 Git
- `package.json` 包含正確的啟動指令
- 伺服器使用 `process.env.PORT` 作為連接埠

### 2. 在 Render 上部署

1. 前往 [Render.com](https://render.com) 並註冊/登入
2. 點擊 "New +" 按鈕
3. 選擇 "Web Service"
4. 連接你的 GitHub 帳號並選擇此專案
5. 設定部署選項：
   - **Name**: `fingerprint-test-site` (或你喜歡的名稱)
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: 選擇免費方案

### 3. 環境變數設定
在 Render 的環境變數中設定：
- `SESSION_SECRET`：session 簽章用的密鑰，正式環境務必設定（`render.yaml` 會自動產生）
- `NODE_ENV`: `production`
- `DB_PATH`（可選）：SQLite 資料庫檔案路徑，預設為專案目錄下的 `fingerprints.db`
- `TRUST_PROXY`：前方代理伺服器的層數，Render 設為 `1`（`render.yaml` 已設定）。部署在代理後方卻沒設定時，所有使用者會被視為同一個 IP，共用限流額度；本機直連時不要設定
- `RATE_LIMIT_API_PER_MINUTE`（可選）：每個 IP 每分鐘可呼叫 API 的次數，預設 100（`GET /api/stats` 不計）
- `RATE_LIMIT_FINGERPRINT_PER_MINUTE`（可選）：每個 IP 每分鐘可提交指紋的次數，預設 10
- `RATE_LIMIT_AUTH_PER_15_MIN`（可選）：每個 IP 每 15 分鐘可登入加註冊的次數，預設 20

### 資料保存注意事項
帳號、指紋與 session 都存在同一個 SQLite 檔案中。Render 免費方案的磁碟是暫存的，**每次重新部署都會清空資料庫**。若需要保留資料，請掛載 persistent disk 並將 `DB_PATH` 指向該磁碟，或改用外部資料庫。

### 4. 部署
點擊 "Create Web Service"，Render 會自動：
- 從 GitHub 拉取程式碼
- 安裝套件
- 啟動應用程式
- 提供公開的 URL

## 專案結構

```
fingerprints/
├── server.js              # Express 伺服器
├── package.json           # 專案設定
├── public/                # 靜態檔案
│   ├── index.html         # 主頁面
│   ├── style.css          # 樣式
│   ├── app.js             # 前端邏輯
│   └── lib/               # FingerprintJS 本地版本
├── test/                  # 測試（node --test）
├── fingerprints.db        # SQLite 資料庫（執行時自動建立，不納入版控）
└── README.md              # 專案說明
```

## API 端點

- `GET /` - 主頁面
- `POST /api/fingerprint` - 提交指紋資料（未登入時只比對不儲存，登入後與帳號綁定儲存）
- `GET /api/fingerprints` - 列出目前登入用戶自己的指紋紀錄（需登入）
- `GET /api/debug/fingerprint/:id` - 查看自己的指紋詳細資料（需登入）
- `GET /api/stats` - 取得統計資料
- `GET /api/captcha` - 取得數學驗證碼
- `POST /api/auth/register` - 用戶註冊
- `POST /api/auth/login` - 用戶登入
- `POST /api/auth/logout` - 用戶登出
- `GET /api/auth/me` - 取得當前用戶資訊

## 技術堆疊

- **後端**: Node.js, Express.js, SQLite（資料與 session 皆存於 SQLite）
- **前端**: HTML5, CSS3, JavaScript (ES6+)
- **指紋採集**: FingerprintJS V4
- **驗證**: express-session + bcryptjs，數學驗證碼
- **部署**: Render

## 授權

MIT License
