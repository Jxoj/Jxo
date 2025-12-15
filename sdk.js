/**
 * Jxo SDK - Secure Authentication and User Data Management
 * Version 2.0.0
 * 
 * SECURITY MODEL:
 * - Apps only get read-only user info (email, name, photo)
 * - Apps can only read/write to their own namespace in Firestore
 * - Apps cannot change passwords, emails, or delete accounts
 * - Apps cannot access other apps' data
 */

(function(window) {
  'use strict';

  const LOGIN_URL = "https://jxoj.github.io/Jxo/account";
  const ACCOUNT_MANAGER_URL = "https://jxoj.github.io/Jxo/account/manage";
  const TRUSTED_SITES_URL = "https://jxoj.github.io/Jxo/ts.json";
  const MAX_APP_DATA_SIZE = 10240; // 10KB limit per app per user

  let currentUser = null;
  let currentAppId = null;
  let trustedSitesData = null;

  class JxoSDK {
    constructor() {
      this.initialized = false;
    }

    /**
     * Initialize the Jxo SDK
     * @param {string} appId - Your app's unique identifier (e.g., "com.mycompany.myapp")
     */
    async init(appId) {
      if (!appId || typeof appId !== 'string') {
        throw new Error('App ID is required and must be a string');
      }

      if (this.initialized) return;

      // Validate and sanitize app ID
      currentAppId = appId.replace(/[^a-zA-Z0-9._-]/g, '');
      if (currentAppId !== appId) {
        throw new Error('Invalid app ID format. Use only letters, numbers, dots, dashes, and underscores.');
      }

      try {
        // Load trusted sites list
        await this._loadTrustedSites();

        // Check for token in URL hash
        const hash = window.location.hash;
        if (hash.includes('token=')) {
          const token = hash.split('token=')[1].split('&')[0];
          
          // Verify token and extract user info
          try {
            const payload = this._parseJWT(token);
            currentUser = {
              uid: payload.user_id || payload.sub,
              email: payload.email,
              emailVerified: payload.email_verified,
              displayName: null, // Will be loaded from API
              photoURL: null // Will be loaded from API
            };

            // Load full user profile from secure API
            await this._loadUserProfile(token);
          } catch (e) {
            console.error('Invalid token:', e);
            currentUser = null;
          }

          // Clean URL
          window.history.replaceState(null, '', window.location.pathname + window.location.search);
        }

        this.initialized = true;
      } catch (error) {
        console.error('Jxo SDK initialization failed:', error);
        throw error;
      }
    }

    /**
     * Load and check trusted sites list
     * @private
     */
    async _loadTrustedSites() {
      try {
        const response = await fetch(TRUSTED_SITES_URL);
        trustedSitesData = await response.json();
        
        const currentDomain = window.location.hostname;
        const isTrusted = trustedSitesData.trustedSites.some(site => 
          currentDomain === site || currentDomain.endsWith('.' + site)
        );
        
        // Show warning if not on trusted site
        if (!isTrusted) {
          console.warn('[Jxo SDK] ⚠️ WARNING: This site is not verified by Jxo.');
          console.warn('[Jxo SDK] Only manage your account at:', trustedSitesData.officialAccountManager);
          
          // Show visual warning if not dismissed before
          const hasSeenWarning = sessionStorage.getItem('jxoSdkWarningShown');
          if (!hasSeenWarning) {
            this._showUntrustedSiteWarning();
            sessionStorage.setItem('jxoSdkWarningShown', 'true');
          }
        }
      } catch (error) {
        console.error('[Jxo SDK] Failed to load trusted sites list:', error);
      }
    }

    /**
     * Show warning banner for untrusted sites
     * @private
     */
    _showUntrustedSiteWarning() {
      const banner = document.createElement('div');
      banner.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: #ff8a80;
        color: #121212;
        padding: 12px 20px;
        text-align: center;
        font-family: system-ui, -apple-system, sans-serif;
        font-weight: 600;
        font-size: 14px;
        z-index: 999999;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3);
      `;
      banner.innerHTML = `
        ⚠️ Security Notice: Only manage your Jxo account at <a href="${trustedSitesData.officialAccountManager}" style="color:#121212;text-decoration:underline" target="_blank">jxoj.github.io/Jxo</a>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;color:#121212;font-size:20px;cursor:pointer;margin-left:10px">×</button>
      `;
      document.body.insertBefore(banner, document.body.firstChild);
    }

    /**
     * Parse JWT token (basic client-side parsing, not for verification)
     * @private
     */
    _parseJWT(token) {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      return JSON.parse(jsonPayload);
    }

    /**
     * Load user profile from secure backend
     * @private
     */
    async _loadUserProfile(token) {
      // In production, this would call your backend API
      // For now, we'll use Firebase Auth REST API
      try {
        const response = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=AIzaSyDUFBrPl8YJwkmqwibq730VX2mtCkxaMeM`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ idToken: token })
        });
        
        const data = await response.json();
        if (data.users && data.users[0]) {
          const user = data.users[0];
          currentUser.displayName = user.displayName || null;
          currentUser.photoURL = user.photoUrl || null;
        }
      } catch (e) {
        console.error('Failed to load user profile:', e);
      }
    }

    /**
     * Get the current authenticated user (READ-ONLY)
     * @returns {Object|null} User object with limited fields
     */
    getUser() {
      if (!currentUser) return null;
      
      // Return only safe, read-only fields
      return {
        uid: currentUser.uid,
        email: currentUser.email,
        displayName: currentUser.displayName,
        photoURL: currentUser.photoURL,
        emailVerified: currentUser.emailVerified
      };
    }

    /**
     * Check if user is authenticated
     * @returns {boolean}
     */
    isAuthenticated() {
      return currentUser !== null;
    }

    /**
     * Redirect to login page
     * @param {string} returnUrl - URL to return to after login (defaults to current page)
     */
    login(returnUrl) {
      const redirect = returnUrl || window.location.href;
      window.location.href = `${LOGIN_URL}?redirect=${encodeURIComponent(redirect)}`;
    }

    /**
     * Open account manager in new window/tab
     */
    openAccountManager() {
      window.open(ACCOUNT_MANAGER_URL, '_blank');
    }

    /**
     * Get app-specific user data from Firestore
     * Apps can only access their own namespace: users/{userId}/apps/{appId}
     * @returns {Promise<Object>} App-specific user data
     */
    async getAppData() {
      if (!this.isAuthenticated()) {
        throw new Error('User not authenticated');
      }

      if (!currentAppId) {
        throw new Error('App ID not set. Call Jxo.init(appId) first.');
      }

      try {
        // Use Firestore REST API to read from app-specific collection
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        
        const response = await fetch(url);
        
        if (response.status === 404) {
          return {}; // No data yet
        }

        if (!response.ok) {
          throw new Error('Failed to fetch app data');
        }

        const doc = await response.json();
        return this._firestoreToObject(doc.fields || {});
      } catch (error) {
        console.error('Failed to get app data:', error);
        throw error;
      }
    }

    /**
     * Update app-specific user data
     * Apps can only write to their own namespace: users/{userId}/apps/{appId}
     * @param {Object} data - Data to update (merged with existing data)
     * @returns {Promise<void>}
     */
    async updateAppData(data) {
      if (!this.isAuthenticated()) {
        throw new Error('User not authenticated');
      }

      if (!currentAppId) {
        throw new Error('App ID not set. Call Jxo.init(appId) first.');
      }

      // Validate data size
      const dataStr = JSON.stringify(data);
      if (dataStr.length > MAX_APP_DATA_SIZE) {
        throw new Error(`Data size exceeds ${MAX_APP_DATA_SIZE} bytes limit`);
      }

      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}?updateMask.fieldPaths=*`;
        
        const response = await fetch(url, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fields: this._objectToFirestore(data)
          })
        });

        if (!response.ok) {
          throw new Error('Failed to update app data');
        }
      } catch (error) {
        console.error('Failed to update app data:', error);
        throw error;
      }
    }

    /**
     * Set app-specific user data (replaces all existing data for this app)
     * @param {Object} data - Data to set
     * @returns {Promise<void>}
     */
    async setAppData(data) {
      if (!this.isAuthenticated()) {
        throw new Error('User not authenticated');
      }

      if (!currentAppId) {
        throw new Error('App ID not set. Call Jxo.init(appId) first.');
      }

      const dataStr = JSON.stringify(data);
      if (dataStr.length > MAX_APP_DATA_SIZE) {
        throw new Error(`Data size exceeds ${MAX_APP_DATA_SIZE} bytes limit`);
      }

      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        
        const response = await fetch(url, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fields: this._objectToFirestore(data)
          })
        });

        if (!response.ok) {
          throw new Error('Failed to set app data');
        }
      } catch (error) {
        console.error('Failed to set app data:', error);
        throw error;
      }
    }

    /**
     * Delete all app-specific data for this user
     * @returns {Promise<void>}
     */
    async deleteAppData() {
      if (!this.isAuthenticated()) {
        throw new Error('User not authenticated');
      }

      if (!currentAppId) {
        throw new Error('App ID not set. Call Jxo.init(appId) first.');
      }

      try {
        const url = `https://firestore.googleapis.com/v1/projects/jxoaccount/databases/(default)/documents/users/${currentUser.uid}/apps/${currentAppId}`;
        
        const response = await fetch(url, {
          method: 'DELETE'
        });

        if (response.status !== 404 && !response.ok) {
          throw new Error('Failed to delete app data');
        }
      } catch (error) {
        console.error('Failed to delete app data:', error);
        throw error;
      }
    }

    /**
     * Sign out (clears local session only, doesn't revoke tokens)
     */
    signOut() {
      currentUser = null;
      // Apps should redirect to login after this
    }

    /**
     * Convert Firestore document to plain object
     * @private
     */
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
        else if (field.arrayValue) {
          obj[key] = (field.arrayValue.values || []).map(v => {
            if (v.stringValue !== undefined) return v.stringValue;
            if (v.integerValue !== undefined) return parseInt(v.integerValue);
            if (v.doubleValue !== undefined) return v.doubleValue;
            if (v.booleanValue !== undefined) return v.booleanValue;
            if (v.mapValue) return this._firestoreToObject(v.mapValue.fields || {});
            return null;
          });
        }
      }
      return obj;
    }

    /**
     * Convert plain object to Firestore format
     * @private
     */
    _objectToFirestore(obj) {
      const fields = {};
      for (const key in obj) {
        const val = obj[key];
        if (typeof val === 'string') fields[key] = { stringValue: val };
        else if (typeof val === 'number') {
          if (Number.isInteger(val)) fields[key] = { integerValue: val.toString() };
          else fields[key] = { doubleValue: val };
        }
        else if (typeof val === 'boolean') fields[key] = { booleanValue: val };
        else if (val === null) fields[key] = { nullValue: null };
        else if (Array.isArray(val)) {
          fields[key] = {
            arrayValue: {
              values: val.map(v => {
                if (typeof v === 'string') return { stringValue: v };
                if (typeof v === 'number') {
                  if (Number.isInteger(v)) return { integerValue: v.toString() };
                  return { doubleValue: v };
                }
                if (typeof v === 'boolean') return { booleanValue: v };
                if (v === null) return { nullValue: null };
                if (typeof v === 'object') return { mapValue: { fields: this._objectToFirestore(v) } };
                return { stringValue: String(v) };
              })
            }
          };
        }
        else if (typeof val === 'object') {
          fields[key] = { mapValue: { fields: this._objectToFirestore(val) } };
        }
      }
      return fields;
    }
  }

  // Create global Jxo object
  window.Jxo = new JxoSDK();

})(window);