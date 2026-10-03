// FingerprintJS 載入管理器（獨立成檔案，Content Security Policy 才能只允許同網站的 script，不必允許內嵌 script）
class FingerprintLoader {
    constructor() {
        this.loaded = false;
        this.loading = false;
        this.loadPromise = null;
    }
    
    async load() {
        if (this.loaded) return true;
        if (this.loading) return this.loadPromise;
        
        this.loading = true;
        // 結束後重設 loading，失敗時下次呼叫才會重新嘗試，而不是一直拿到同一個失敗結果
        this.loadPromise = this.tryLoadSources().finally(() => {
            this.loading = false;
        });
        return this.loadPromise;
    }
    
    async tryLoadSources() {
        // 只載入與網頁同一個 server 提供的本地版本：
        // 外部 CDN 的浮動版本（@4）沒有 SRI 檢查，CDN 出問題時會在本頁執行未經驗證的程式碼，能讀到登入表單輸入的密碼
        const sources = [
            'lib/fingerprintjs.min.js'
        ];
        
        for (let i = 0; i < sources.length; i++) {
            const src = sources[i];
            console.log(`嘗試載入 FingerprintJS 來源 ${i + 1}/${sources.length}: ${src}`);
            
            try {
                await this.loadScript(src, 10000); // 10秒超時
                if (typeof FingerprintJS !== 'undefined') {
                    console.log('FingerprintJS 載入成功:', src);
                    this.loaded = true;
                    return true;
                }
            } catch (error) {
                console.warn(`載入失敗 ${src}:`, error.message);
                continue;
            }
        }
        
        throw new Error('所有 FingerprintJS 載入來源都失敗');
    }
    
    loadScript(src, timeout = 10000) {
        return new Promise((resolve, reject) => {
            const script = document.createElement('script');
            const timeoutId = setTimeout(() => {
                script.remove();
                reject(new Error(`載入超時: ${src}`));
            }, timeout);
            
            script.onload = () => {
                clearTimeout(timeoutId);
                resolve();
            };
            
            script.onerror = () => {
                clearTimeout(timeoutId);
                script.remove();
                reject(new Error(`載入錯誤: ${src}`));
            };
            
            script.src = src;
            script.crossOrigin = 'anonymous';
            document.head.appendChild(script);
        });
    }
}

// 全域載入器實例
window.fingerprintLoader = new FingerprintLoader();

// 檢查 FingerprintJS 載入狀態
window.addEventListener('load', () => {
    console.log('頁面載入完成');
    console.log('FingerprintJS 狀態:', typeof FingerprintJS !== 'undefined' ? '已載入' : '未載入');
});
