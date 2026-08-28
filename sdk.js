(function(window) {
  'use strict';

  const LOGIN_URL = "https://jxoj.github.io/Jxo/account";
  const ACCOUNT_MANAGER_URL = "https://jxoj.github.io/Jxo/account/manage";
  const TRUSTED_SITES_URL = "https://jxoj.github.io/Jxo/ts.json";
  const MAX_APP_DATA_SIZE = 10240;

  let currentUser = null;
  let currentAppId = null;
  let trustedSitesData = null;

  class JxoSDK {
    constructor() {
      this.initialized = false;
      this.token = null; // Track user token securely
    }

    async init(appId) {
      if (!appId || typeof appId !== 'string') throw new Error('App ID required');
      if (this.initialized) return;

      currentAppId = appId.replace(/[^a-zA-Z0-9._-]/g, '');
      try {
        await this._loadTrustedSites();
        const hash = window.location.hash;
        if (hash.includes('token=')) {
          this.token = hash.split('token=')[1].split('&')[0];
          const payload = this._parseJWT(this.token);
          currentUser = {
            uid: payload.user_id || payload.sub,
            email: payload.email,
            emailVerified: payload.email_verified,
            displayName: null, photoURL: null
          };
          await this._loadUserProfile(this.token);
        }
        window.history.replaceState(null, '', window.location.pathname + window.location.search);
        this.initialized = true;
      } catch (error) {
        console.error('Jxo SDK initialization failed:', error);
        throw error;
      }
    }

    async getAppData() {
      if (!this.isAuthenticated() || !currentAppId) throw new Error('Not authenticated');
      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        const response = await fetch(url, {
          headers: { 'Authorization': `Bearer ${this.token}` }
        });
        if (response.status === 404) return {};
        if (!response.ok) throw new Error('Failed to fetch app data');
        const doc = await response.json();
        return this._firestoreToObject(doc.fields || {});
      } catch (error) {
        throw error;
      }
    }

    async updateAppData(data) {
      if (!this.isAuthenticated() || !currentAppId) throw new Error('Not authenticated');
      if (JSON.stringify(data).length > MAX_APP_DATA_SIZE) throw new Error('Exceeds limit');
      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}?updateMask.fieldPaths=*`;
        const response = await fetch(url, {
          method: 'PATCH',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          },
          body: JSON.stringify({ fields: this._objectToFirestore(data) })
        });
        if (!response.ok) throw new Error('Failed to update app data');
      } catch (error) {
        throw error;
      }
    }

    async setAppData(data) {
      if (!this.isAuthenticated() || !currentAppId) throw new Error('Not authenticated');
      if (JSON.stringify(data).length > MAX_APP_DATA_SIZE) throw new Error('Exceeds limit');
      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        const response = await fetch(url, {
          method: 'PATCH',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.token}`
          },
          body: JSON.stringify({ fields: this._objectToFirestore(data) })
        });
        if (!response.ok) throw new Error('Failed to set app data');
      } catch (error) {
        throw error;
      }
    }

    async deleteAppData() {
      if (!this.isAuthenticated() || !currentAppId) throw new Error('Not authenticated');
      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        const response = await fetch(url, {
          method: 'DELETE',
          headers: { 'Authorization': `Bearer ${this.token}` }
        });
        if (response.status !== 404 && !response.ok) throw new Error('Failed to delete app data');
      } catch (error) {
        throw error;
      }
    }

    async _loadTrustedSites() {
      try {
        const response = await fetch(TRUSTED_SITES_URL);
        trustedSitesData = await response.json();
        const currentDomain = window.location.hostname;
        const isTrusted = trustedSitesData.trustedSites.some(site => currentDomain === site || currentDomain.endsWith('.' + site));
        if (!isTrusted && !sessionStorage.getItem('jxoSdkWarningShown')) {
          this._showUntrustedSiteWarning();
          sessionStorage.setItem('jxoSdkWarningShown', 'true');
        }
      } catch (error) {
        console.error('Trusted sites failed:', error);
      }
    }

    _showUntrustedSiteWarning() {
      const banner = document.createElement('div');
      banner.style.cssText = `position:fixed;top:0;left:0;right:0;background:#ff8a80;color:#121212;padding:12px;text-align:center;z-index:999999;`;
      banner.innerHTML = `⚠️ Security Notice: Manage account at <a href="${trustedSitesData.officialAccountManager}">jxoj.github.io/Jxo</a>`;
      document.body.insertBefore(banner, document.body.firstChild);
    }

    _parseJWT(token) {
      const base64Url = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(decodeURIComponent(atob(base64Url).split('').map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2)).join('')));
    }

    async _loadUserProfile(token) {
      try {
        const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=AIzaSyDUFBrPl8YJwkmqwibq730VX2mtCkxaMeM`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: token })
        });
        const data = await response.json();
        if (data.users && data.users[0]) {
          currentUser.displayName = data.users[0].displayName || null;
          currentUser.photoURL = data.users[0].photoUrl || null;
        }
      } catch (e) {
        console.error('User profile failed:', e);
      }
    }

    getUser() { return currentUser ? { ...currentUser } : null; }
    isAuthenticated() { return currentUser !== null; }
    login(returnUrl) { window.location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(returnUrl || window.location.href)}`; }
    openAccountManager() { window.open(ACCOUNT_MANAGER_URL, '_blank'); }
    signOut() { currentUser = null; this.token = null; }

    _firestoreToObject(fields) {
      const obj = {};
      for (const key in fields) {
        const field = fields[key];
        if (field.stringValue !== undefined) obj[key] = field.stringValue;
        else if (field.integerValue !== undefined) obj[key] = parseInt(field.integerValue);
        else if (field.doubleValue !== undefined) obj[key] = field.doubleValue;
        else if (field.booleanValue !== undefined) obj[key] = field.booleanValue;
        else if (field.nullValue !== undefined) obj[key] = null;
        else if (field.mapValue) obj[key] = this._firestoreToObject(field.mapValue.fields || {});
      }
      return obj;
    }

    _objectToFirestore(obj) {
      const fields = {};
      for (const key in obj) {
        const val = obj[key];
        if (typeof val === 'string') fields[key] = { stringValue: val };
        else if (typeof val === 'number') {
          fields[key] = Number.isInteger(val) ? { integerValue: val.toString() } : { doubleValue: val };
        } else if (typeof val === 'boolean') fields[key] = { booleanValue: val };
        else if (val === null) fields[key] = { nullValue: null };
        else if (typeof val === 'object') fields[key] = { mapValue: { fields: this._objectToFirestore(val) } };
      }
      return fields;
    }
  }

  window.Jxo = new JxoSDK();
})(window);
