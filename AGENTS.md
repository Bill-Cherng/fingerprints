# Repository Guidelines

## Project Structure & Module Organization
Source logic lives in `server.js`, which wires Express routes, SQLite models, and helpers such as `calculateMultiFingerprintSimilarity`. Public assets reside under `public/` (`index.html`, `style.css`, `app.js`, `lib/fingerprintjs.min.js`) and are served as-is. Tests live in `test/`. The SQLite database (`fingerprints.db`) is created at runtime and is not committed.

## Build, Test, and Development Commands
- `npm install`: Installs Express, sqlite3, nodemon, and other required packages.
- `npm run dev`: Starts the hot-reload server on `http://localhost:3000` for day-to-day changes.
- `npm start`: Boots the production server, mirroring Render’s deployment entrypoint.
- `npm run test:e2e`: Runs the browser tests in `e2e/` with Playwright and Chromium (run `npx playwright install chromium` once first).
- `npm test`: Runs the test suite in `test/*.test.js` with the Node.js built-in test runner; CI runs it on Node 22/24 (`package.json` requires Node 22+; `.node-version` pins Render to 22).

## Coding Style & Naming Conventions
Use 4-space indentation, single quotes, and trailing semicolons across Node and browser scripts. Favor `async/await` flows and keep helpers pure when feasible. Name modules and functions in clear English (e.g., `collectFingerprint`, `calculateCanvasSimilarity`). Document localized UI copy directly in the front-end assets.

## Testing Guidelines
Tests use `node:test` and run against an in-memory database (`DB_PATH=:memory:`). API tests start the Express app on a random port and call it with `fetch`. Add a regression test for every bug fix and confirm it fails without the fix. Run `npm test` before proposing changes and note manual regression steps when automated coverage is insufficient.

## Commit & Pull Request Guidelines
Follow the repository’s Chinese commit format, e.g., `修正相似度計算問題：1) 調整閾值 2) 更新測試`. Reference related issues and mention database or configuration adjustments. Pull requests should explain motivation, list validation steps (commands run, datasets), and attach UI screenshots or JSON payloads whenever responses change.

## Security & Configuration Tips
Load secrets like `SESSION_SECRET` from environment variables; never commit credentials. The server refuses to start in production (`NODE_ENV=production`) without `SESSION_SECRET`. Behind a proxy such as Render, set `TRUST_PROXY` so rate limiting and secure cookies see the real client IP and protocol. Never commit database files, cookies, or other runtime data.
