(function(window) {
  'use strict';

  const LOGIN_URL = "https://jxoj.github.io/Jxo/account";
  const ACCOUNT_MANAGER_URL = "https://jxoj.github.io/Jxo/account/manage";
  const BRIDGE_URL = "https://jxoj.github.io/Jxo/account/bridge/";
  const TRUSTED_SITES_URL = "https://jxoj.github.io/Jxo/ts.json";

  class JxoSDK {
    constructor() {
      this.initialized = false;
      this.appId = null;
      this.user = null;
      this.bridge = null;
      this.pending = new Map();
      this.messageHandler = event => this._handleMessage(event);
    }

    async init(appId) {
      if (!appId || typeof appId !== 'string') throw new Error('App ID required');
      if (this.initialized) return;
      this.appId = appId.replace(/[^a-zA-Z0-9._-]/g, '');
      await this._loadTrustedSites();
      window.addEventListener('message', this.messageHandler);
      this.bridge = document.createElement('iframe');
      this.bridge.src = BRIDGE_URL;
      this.bridge.title = 'Jxo authentication bridge';
      this.bridge.hidden = true;
      document.body.appendChild(this.bridge);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('Jxo auth bridge timed out')), 10000);
        this._bridgeReady = () => { clearTimeout(timer); resolve(); };
      });
      this.user = await this._request('user');
      this.initialized = true;
    }

    _handleMessage(event) {
      if (event.source !== this.bridge?.contentWindow || event.origin !== 'https://jxoj.github.io') return;
      if (event.data?.type === 'ready') {
        this._bridgeReady?.();
        return;
      }
      const request = this.pending.get(event.data?.requestId);
      if (!request) return;
      this.pending.delete(event.data.requestId);
      event.data.error ? request.reject(new Error(event.data.error)) : request.resolve(event.data.result);
    }

    _request(action, data) {
      if (!this.bridge?.contentWindow) return Promise.reject(new Error('Jxo SDK is not initialized'));
      const requestId = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      return new Promise((resolve, reject) => {
        this.pending.set(requestId, { resolve, reject });
        this.bridge.contentWindow.postMessage({ target: 'jxo-auth-bridge', action, appId: this.appId, data, requestId }, 'https://jxoj.github.io');
      });
    }

    async _loadTrustedSites() {
      try {
        const data = await (await fetch(TRUSTED_SITES_URL, { cache: 'no-store' })).json();
        const trusted = (data.trustedSites || []).some(site => window.location.hostname === site || window.location.hostname.endsWith(`.${site}`));
        if (!trusted && !sessionStorage.getItem('jxoSdkWarningShown')) {
          const banner = document.createElement('div');
          banner.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#ff8a80;color:#121212;padding:12px;text-align:center;z-index:999999;';
          banner.innerHTML = `Security notice: sign in only on trusted sites. <a href="${data.officialAccountManager}">Open Jxo Account</a>`;
          document.body.prepend(banner);
          sessionStorage.setItem('jxoSdkWarningShown', 'true');
        }
      } catch (error) { console.warn('Trusted sites failed:', error); }
    }

    getAppData() { return this._request('get'); }
    updateAppData(data) { return this._request('update', data); }
    setAppData(data) { return this._request('set', data); }
    deleteAppData() { return this._request('delete'); }
    getUser() { return this.user ? { ...this.user } : null; }
    isAuthenticated() { return this.user !== null; }
    login(returnUrl) { window.location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(returnUrl || window.location.href)}`; }
    openAccountManager() { window.open(ACCOUNT_MANAGER_URL, '_blank', 'noopener'); }
    signOut() { this.user = null; }
  }

  window.Jxo = new JxoSDK();
})(window);
