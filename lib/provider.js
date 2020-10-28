/*
 * @license
 * Copyright 2016 The Advanced REST client authors <arc@mulesoft.com>
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
import { BrowserWindow, session, net } from 'electron';
import { URLSearchParams } from 'url';
import Store from 'electron-store';
import i18n from 'i18n';
import { AuthError } from './AuthError.js';

const windowParams = {
  width: 640,
  height: 800,
  alwaysOnTop: false,
  autoHideMenuBar: true,
  show: true,
  webPreferences: {
    contextIsolation: true,
    nodeIntegration: false,
    nodeIntegrationInWorker: false,
    enableRemoteModule: false,
    experimentalFeatures: false,
    allowRunningInsecureContent: false,
  },
};

/** @typedef {import('@advanced-rest-client/arc-types').OAuth2.TokenInfo} TokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2CustomData} OAuth2CustomData */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2AuthorizationRequestCustomData} OAuth2AuthorizationRequestCustomData */
/** @typedef {import('./provider').CodeResponseObject} CodeResponseObject */

/**
 * A class to perform OAuth2 flow with given configuration.
 *
 * See README.md file for detailed description.
 */
export class IdentityProvider {
  /**
   *
   * @param {String} id ID of the provider.
   * @param {OAuth2Authorization=} oauthConfig OAuth2 configuration.
   */
  constructor(id, oauthConfig) {
    /**
     * Generated ID for the provider.
     *
     * @type {String}
     */
    this.id = id;
    /**
     * OAuth2 configuration for this provider.
     * If not set the settings argument from calling oauth flow function must
     * contain all properties.
     * This is configuration object used when the OAuth configuration is read
     * from the package.json file.
     * @type {OAuth2Authorization}
     */
    // @ts-ignore
    this.oauthConfig = oauthConfig || {};
    /**
     * In memory cached token data
     * @type {TokenInfo}
     */
    this.tokenInfo = undefined;
    /**
     * Cached token key id in the persistent store.
     * @type {String}
     */
    this.cacheKey = `_oauth_cache_${this.id}`;
    /**
     * Latest generated state parameter for the request.
     * If the settings object when calling any of the request OAuth flow
     * methods has state parameter, it will be used.
     * @type {String}
     */
    this._state = undefined;
    /**
     * Instance of the store library to cache token data.
     * @type {Store}
     */
    this.tokenStore = new Store({
      name: 'electron-oauth',
      encryptionKey: 'd622dbf0-a470-4048-95f9-400ef02a2397',
    });
    this._sessionCompletedListener = this._sessionCompletedListener.bind(this);
    this._startSession();
    this._authWindowCloseHandler = this._authWindowCloseHandler.bind(this);
    /**
     * The user agent to be set on the browser window when requesting for a token
     * in a browser flow. This allows to fix the issue with Google auth servers that
     * stopped supporting default electron user agent.
     */
    this.userAgent = 'Chrome';
  }

  /**
   * Enables session in module's partition.
   */
  _startSession() {
    this._session = session.fromPartition(`persist:oauth2-win-${ this.id}`);
    this._session.webRequest.onCompleted(this._sessionCompletedListener);
  }

  /**
   * Clears the state of the element.
   */
  clear() {
    this._state = undefined;
    this._settings = undefined;
    this.__lastPromise = undefined;
    this.unobserveAuthWindow();
  }

  /**
   * Clears token cache data and current token information.
   */
  clearCache() {
    if (this.tokenStore.has(this.cacheKey)) {
      this.tokenStore.delete(this.cacheKey);
    }
    this.tokenInfo = undefined;
  }

  /**
   * Gets either cached authorization token or request for new one.
   *
   * If the `interactive` flag is false the authorization prompt
   * window will never be opened and if the authorization scope has
   * changed or user did not authorized the application this will
   * result in Promise error.
   *
   * @param {OAuth2Authorization=} opts Authorization options
   * @return {Promise<TokenInfo>} A promise resulted to the auth token.
   * It return undefined if the app is not authorized. The promise will result
   * with error (reject) if there's an authorization error.
   */
  async getAuthToken(opts={}) {
    this._settings = opts;
    try {
      const info = await this.getTokenInfo();
      const scopes = opts.scopes || this.oauthConfig.scopes;
      if (info && this.isTokenAuthorized(info, scopes)) {
        delete info.state;
        if (opts.state) {
          info.state = opts.state;
        }
        return info;
      }
      return await this.launchWebAuthFlow(opts);
    } catch (cause) {
      if (opts.interactive === false) {
        return;
      }
      const err = new AuthError(cause.message, cause.code);
      throw err;
    }
  }

  /**
   * Runs the web authorization flow.
   * @param {OAuth2Authorization=} opts Authorization options
   * @return {Promise<TokenInfo>} A promise with auth result.
   */
  launchWebAuthFlow(opts={}) {
    this.tokenInfo = undefined;
    this._type = opts.responseType || this.oauthConfig.responseType;
    this._state = opts.state || this.randomString();
    this._settings = opts;
    switch (this._type) {
    case 'implicit':
    case 'token':
      return this._authorize(this._constructPopupUrl(opts, 'token'), opts);
    case 'authorization_code':
    case 'code':
      return this._authorize(this._constructPopupUrl(opts, 'code'), opts);
    case 'client_credentials':
      return this.authorizeClientCredentials(opts);
    case 'password':
      return this.authorizePassword(opts);
    default:
      return this.authorizeCustomGrant(opts);
    }
  }

  /**
   * Browser or server flow: open the initial popup.
   * @param {OAuth2Authorization} settings Settings passed to the authorize function.
   * @param {String} type `token` or `code`
   * @return {String} Full URL for the endpoint.
   */
  _constructPopupUrl(settings, type) {
    const cnf = this.oauthConfig;
    let url = settings.authorizationUri || cnf.authorizationUri;
    if (url.indexOf('?') === -1) {
      url += '?';
    } else {
      url += '&';
    }
    const parts = [];
    parts[parts.length] = `response_type=${type}`;
    const cid = settings.clientId || cnf.clientId || '';
    parts[parts.length] = `client_id=${ encodeURIComponent(cid)}`;
    const rUri = settings.redirectUri || cnf.redirectUri;
    if (rUri) {
      parts[parts.length] = `redirect_uri=${encodeURIComponent(rUri)}`;
    }
    const scopes = settings.scopes || this.oauthConfig.scopes;
    if (scopes && scopes.length) {
      parts[parts.length] = `scope=${this._computeScope(scopes)}`;
    }
    parts[parts.length] = `state=${encodeURIComponent(this._state)}`;
    if (settings.includeGrantedScopes || cnf.includeGrantedScopes) {
      parts[parts.length] = 'include_granted_scopes=true';
    }
    const lh = settings.loginHint || settings.loginHint;
    if (lh) {
      parts[parts.length] = `login_hint=${encodeURIComponent(lh)}`;
    }
    if (settings.interactive === false) {
      parts[parts.length] = 'prompt=none';
    }
    url += parts.join('&');
    // custom query parameters from `auth-methods` ARC component
    if (settings.customData) {
      const cs = settings.customData.auth;
      if (cs) {
        url = this._applyCustomSettingsQuery(url, cs);
      }
    }
    return url;
  }

  /**
   * Computes `scope` URL parameter from scopes array.
   *
   * @param {string[]} scopes List of scopes to use with the request.
   * @return {string} Computed scope value.
   */
  _computeScope(scopes) {
    if (!scopes) {
      return '';
    }
    if (typeof scopes === 'string') {
      return scopes;
    }
    if (Array.isArray(scopes)) {
      const scope = scopes.join(' ');
      return encodeURIComponent(scope);
    }
  }

  /**
   * Authorizes the user in the OAuth authorization endpoint.
   * By default it authorizes the user using a popup that displays
   * authorization screen. When `interactive` property is set to `false`
   * on the `settings` object then it will not render `BrowserWindow`.
   *
   * @param {string} authUrl Complete authorization url
   * @param {OAuth2Authorization} settings Passed user settings
   * @return {Promise<TokenInfo>}
   */
  _authorize(authUrl, settings) {
    this._settings = settings;
    const params = { ...windowParams };
    params.webPreferences.session = this._session;
    if (settings.interactive === false) {
      params.show = false;
    }
    const win = new BrowserWindow(params);
    win.loadURL(authUrl, { userAgent: this.userAgent });
    this._observeAuthWindowNavigation(win);
    this.currentOAuthWindow = win;
    return new Promise((resolve, reject) => {
      this.__lastPromise = {
        resolve,
        reject,
      };
    });
  }

  /**
   * Adds listeners to a window object.
   *
   * @param {BrowserWindow} win Window object to observe events on.
   */
  _observeAuthWindowNavigation(win) {
    this._oauthWindowListening = true;
    win.on('closed', this._authWindowCloseHandler);
  }

  /**
   * Removes event listeners, closes the window and cleans the property.
   */
  unobserveAuthWindow() {
    this._oauthWindowListening = false;
    const win = this.currentOAuthWindow;
    if (!win) {
      return;
    }
    win.removeListener('closed', this._authWindowCloseHandler);
    win.destroy();
    delete this.currentOAuthWindow;
  }

  /**
   * Reports authorization error back to the application.
   *
   * This operation clears the promise object.
   *
   * @param {AuthError} error Error details to report to the app.
   * It should contain `code` and `message` properties.
   */
  _reportOAuthError(error) {
    this.unobserveAuthWindow();
    if (!this.__lastPromise) {
      return;
    }
    error.interactive = this._settings.interactive;
    this.__lastPromise.reject(error);
    delete this.__lastPromise;
    this.clear();
  }

  /**
   * Parses response URL and reports the result of the request.
   *
   * @param {string} url Redirected response URL
   */
  _reportOAuthResult(url) {
    this.unobserveAuthWindow();
    let params = '';
    if (this._type === 'token' || this._type === 'implicit') {
      params = url.substr(url.indexOf('#') + 1);
    } else {
      params = url.substr(url.indexOf('?') + 1);
    }
    const oauthParams = new URLSearchParams(params);
    this._processPopupResponseData(oauthParams);
  }

  /**
   * Processes OAuth2 server query string response.
   *
   * @param {URLSearchParams} oauthParams Created from parameters params.
   */
  _processPopupResponseData(oauthParams) {
    const state = oauthParams.get('state');
    if (!state) {
      this._reportOAuthError(new AuthError(i18n.__('ERR_SERVER_STATE'), 'no_state', this._state));
    } else if (state !== this._state) {
      this._reportOAuthError(new AuthError(i18n.__('ERR_STATE_MISMATCH'), 'invalid_state', this._state));
    } else if (oauthParams.has('error')) {
      this._reportOAuthError(this._createResponseError(oauthParams));
    } else if (this._type === 'implicit' || this._type === 'token') {
      this._handleTokenInfo(this._tokenInfoFromParams(oauthParams));
    } else if (this._type === 'authorization_code' || this._type === 'code') {
      this._exchangeCode(oauthParams.get('code'));
    }
  }

  /**
   * Creates a token info object from query parameters
   * @param {URLSearchParams} oauthParams
   * @return {TokenInfo}
   */
  _tokenInfoFromParams(oauthParams) {
    const accessToken = oauthParams.get('access_token');
    const tokenType = oauthParams.get('token_type');
    const expiresIn = Number(oauthParams.get('expires_in'));
    const scope = this._computeTokenInfoScopes(oauthParams.get('scope'));
    const tokenInfo = /** @type TokenInfo */ ({
      accessToken,
      tokenType,
      expiresIn,
      state: oauthParams.get('state'),
      scope,
      expiresAt: undefined,
      expiresAssumed: false,
    });
    this.computeExpires(tokenInfo);
    return tokenInfo;
  }

  /**
   * Computes the final list of granted scopes.
   * It is a list of scopes received in the response or the list of requested scopes.
   * Because the user may change the list of scopes during authorization
   * the received list of scopes can be different than the one requested by the user.
   *
   * @param {string} scope The `scope` parameter received with the response. May be
   * `undefined`.
   * @return {string[]|undefined} The list of scopes for the token.
   */
  _computeTokenInfoScopes(scope) {
    const requestedScopes = this._settings.scopes || this.oauthConfig.scopes;
    if (!scope && requestedScopes) {
      return requestedScopes;
    }
    let listScopes = [];
    if (scope) {
      listScopes = scope.split(' ');
      if (requestedScopes) {
        listScopes = requestedScopes.concat(listScopes);
      }
    }
    return listScopes;
  }

  /**
   * Resolves the main promise with token data.
   * @param {TokenInfo} info Auth token information
   */
  _handleTokenInfo(info) {
    this.tokenInfo = info;
    this.storeToken(info);
    if (!this.__lastPromise) {
      return;
    }
    info.interactive = this._settings.interactive;
    if (!info.state) {
      info.state = this._state;
    }
    this.__lastPromise.resolve({ ...info });
    delete this.__lastPromise;
    this.clear();
  }

  /**
   * Handler fore an error that happened during code exchange.
   * @param {Error} e
   */
  _handleTokenCodeError(e) {
    this._reportOAuthError(new AuthError(e.message, 'uri_error', this._state));
  }

  /**
   * Exchange code for token.
   *
   * @param {String} code Returned code from the authorization endpoint.
   * @return {Promise<void>}
   */
  async _exchangeCode(code) {
    const url = this._settings.accessTokenUri || this.oauthConfig.accessTokenUri;
    const body = this._getCodeExchangeBody(this._settings, code);
    try {
      const tokenInfo = await this._requestToken(url, body, this._settings);
      await this._handleTokenInfo(tokenInfo);
    } catch (cause) {
      this._handleTokenCodeError(cause);
    }
  }

  /**
   * Returns a body value for the code exchange request.
   * @param {OAuth2Authorization} settings Initial settings object.
   * @param {string} code Authorization code value returned by the authorization
   * server.
   * @return {string} Request body.
   */
  _getCodeExchangeBody(settings, code) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.clientId || '';
    const rUri = settings.redirectUri || cnf.redirectUri;
    const cs = settings.clientSecret || cnf.clientSecret;
    let url = 'grant_type=authorization_code';
    url += `&client_id=${ encodeURIComponent(cid)}`;
    if (rUri) {
      url += `&redirect_uri=${ encodeURIComponent(rUri)}`;
    }
    url += `&code=${ encodeURIComponent(code)}`;
    if (cs) {
      url += `&client_secret=${ encodeURIComponent(cs)}`;
    } else {
      url += '&client_secret=';
    }
    return url;
  }

  /**
   * Camel case given name.
   *
   * @param {string} name Value to camel case.
   * @return {string|undefined} Camel cased name
   */
  _camel(name) {
    let i = 0;
    let l;
    let changed = false;
    while ((l = name[i])) {
      if ((l === '_' || l === '-') && i + 1 < name.length) {
        name = name.substr(0, i) + name[i + 1].toUpperCase() +
          name.substr(i + 2);
        changed = true;
      }
      i++;
    }
    return changed ? name : undefined;
  }

  /**
   * Requests for token from the authorization server for `code`, `password`,
   * `client_credentials` and custom grant types.
   *
   * @param {string} url Base URI of the endpoint. Custom properties will be
   * applied to the final URL.
   * @param {string} body Generated body for given type. Custom properties will
   * be applied to the final body.
   * @param {OAuth2Authorization} settings Settings object passed to the `authorize()`
   * function
   * @return {Promise<TokenInfo>} Promise resolved to the response string.
   */
  _requestToken(url, body, settings) {
    if (settings.customData) {
      const cs = settings.customData.token;
      if (cs) {
        url = this._applyCustomSettingsQuery(url, cs);
      }
      body = this._applyCustomSettingsBody(body, settings.customData);
    }
    return new Promise((resolve, reject) => {
      const request = net.request({
        method: 'POST',
        session: this._session,
        url,
      });
      request.setHeader('Content-Type', 'application/x-www-form-urlencoded');
      if (settings.customData) {
        this._applyCustomSettingsHeaders(request, settings.customData);
      }
      request.on('response', (response) => {
        const ro = {
          status: response.statusCode,
          headers: response.headers,
          body: '',
        };
        response.on('data', (chunk) => {
          ro.body += chunk;
        });
        response.on('end', () =>
          this._processTokenResponseHandler(ro, resolve, reject));
        request.on('error', (error) =>
          this._processTokenResponseErrorHandler(error, reject));
      });
      request.on('error', (error) =>
        this._processTokenResponseErrorHandler(error, reject));
      request.write(body);
      request.end();
    });
  }

  /**
   * Handler for the code request error event.
   * Rejects the promise with error description.
   *
   * @param {Error} error An error object
   * @param {Function} reject Promise's reject function.
   */
  _processTokenResponseErrorHandler(error, reject) {
    let message = i18n.__('ERR_REQUEST_FAILED');
    if (error && error.message) {
      message += ` ${error.message}`;
    }
    reject(new Error(message));
  }

  /**
   * Handler for the code request load event.
   * Processes the response and either rejects the promise with an error
   * or resolves it to token info object.
   *
   * @param {CodeResponseObject} response A response containing `status` and `body  `
   * @param {Function} resolve Resolve function
   * @param {Function} reject Reject function
   */
  _processTokenResponseHandler(response, resolve, reject) {
    const { status, body } = response;
    if (status === 404) {
      const message = i18n.__('ERR_CODE_404');
      reject(new Error(message));
      return;
    } else if (status >= 400 && status < 500) {
      const message = i18n.__(`Client error: %s`, body);
      reject(new Error(message));
      return;
    } else if (status >= 500) {
      const message = i18n.__(`Authorization server error. Response code is`, String(status));
      reject(new Error(message));
      return;
    }
    let tokenInfo;
    try {
      tokenInfo = this._processCodeResponse(body, response.headers['content-type']);
    } catch (e) {
      reject(new Error(e.message));
      return;
    }
    resolve(tokenInfo);
  }

  /**
   * Processes token request body and produces map of values.
   *
   * @param {string} body Body received in the response.
   * @param {string} contentType Response content type.
   * @return {TokenInfo} Response as an object.
   * @throws {Error} Exception when body is invalid.
   */
  _processCodeResponse(body, contentType) {
    if (!body) {
      throw new Error(i18n.__('ERR_CODE_RESPONSE_EMPTY'));
    }
    if (Array.isArray(contentType)) {
      [contentType] = contentType;
    }
    let tokenInfo;
    if (contentType.indexOf('json') !== -1) {
      tokenInfo = JSON.parse(body);
      for (const name in tokenInfo) {
        if (Object.prototype.hasOwnProperty.call(tokenInfo, name)) {
          const camelName = this._camel(name);
          if (camelName) {
            tokenInfo[camelName] = tokenInfo[name];
          }
        }
      }
    } else {
      tokenInfo = {};
      body.split('&').forEach((p) => {
        const item = p.split('=');
        const name = item[0];
        const camelName = this._camel(name);
        const value = decodeURIComponent(item[1]);
        tokenInfo[name] = value;
        tokenInfo[camelName] = value;
      });
    }
    this.computeExpires(tokenInfo);
    return tokenInfo;
  }

  /**
   * Applies custom properties defined in the OAuth settings object to the URL.
   *
   * @param {string} url Generated URL for an endpoint.
   * @param {OAuth2AuthorizationRequestCustomData} data `customData.[type]` property from the settings object.
   * The type is either `auth` or `token`.
   * @return {string}
   */
  _applyCustomSettingsQuery(url, data) {
    if (!data || !data.parameters) {
      return url;
    }
    const char = url.indexOf('?') === -1 ? '?' : '&';
    url += char + data.parameters.map((item) => {
      let value = item.value;
      if (value) {
        value = encodeURIComponent(value);
      } else {
        value = '';
      }
      return `${encodeURIComponent(item.name)}=${value}`;
    }).join('&');
    return url;
  }

  /**
   * Applies custom headers from the settings object
   *
   * @param {Electron.ClientRequest} request Instance of the request object.
   * @param {OAuth2CustomData} data Value of settings' `customData` property
   */
  _applyCustomSettingsHeaders(request, data) {
    if (!data || !data.token || !data.token.headers) {
      return;
    }
    data.token.headers.forEach((item) => {
      try {
        request.setHeader(item.name, item.value);
      } catch (e) {
        // ..
      }
    });
  }

  /**
   * Applies custom body properties from the settings to the body value.
   *
   * @param {string} body Already computed body for OAuth request. Custom
   * properties are appended at the end of OAuth string.
   * @param {OAuth2CustomData} data Value of settings' `customData` property
   * @return {string} Request body
   */
  _applyCustomSettingsBody(body, data) {
    if (!data || !data.token || !data.token.body) {
      return body;
    }
    const dataArr = data.token.body.map((item) => {
      let value = item.value;
      if (value) {
        value = encodeURIComponent(value);
      } else {
        value = '';
      }
      return `${encodeURIComponent(item.name)}=${ value}`;
    });
    body += `&${dataArr.join('&')}`;
    return body;
  }

  /**
   * Requests a token for `password` request type.
   *
   * @param {OAuth2Authorization} settings The same settings as passed to `authorize()`
   * function.
   * @return {Promise<TokenInfo>} Promise resolved to token info.
   */
  async authorizePassword(settings) {
    this._settings = settings;
    const url = settings.accessTokenUri || this.oauthConfig.accessTokenUri;
    const body = this._getPasswordBody(settings);
    try {
      const info = await this._requestToken(url, body, settings);
      this.tokenInfo = info;
      await this.storeToken(info);
      return info;
    } catch (cause) {
      throw new AuthError(cause.message, 'uri_error', this._state);
    }
  }

  /**
   * Generates a payload message for password authorization.
   *
   * @param {OAuth2Authorization} settings Settings object passed to the `authorize()`
   * function
   * @return {string} Message body as defined in OAuth2 spec.
   */
  _getPasswordBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.clientId || '';
    const scopes = settings.scopes || this.oauthConfig.scopes;
    const parts = [];
    parts[parts.length] = 'grant_type=password';
    parts[parts.length] = `username=${encodeURIComponent(settings.username)}`;
    parts[parts.length] = `password=${encodeURIComponent(settings.password)}`;
    if (cid) {
      parts[parts.length] = `client_id=${encodeURIComponent(cid)}`;
    }
    if (scopes && scopes.length) {
      parts[parts.length] = `scope=${this._computeScope(scopes)}`;
    }
    return parts.join('&');
  }

  /**
   * Requests a token for `client_credentials` request type.
   *
   * @param {OAuth2Authorization} settings The same settings as passed to `authorize()`
   * function.
   * @return {Promise<TokenInfo>} Promise resolved to a token info object.
   */
  async authorizeClientCredentials(settings) {
    this._settings = settings;
    const url = this._settings.accessTokenUri || this.oauthConfig.accessTokenUri;
    const body = this._getClientCredentialsBody(settings);
    try {
      const info = await this._requestToken(url, body, settings);
      this.tokenInfo = info;
      await this.storeToken(info);
      return info;
    } catch (cause) {
      throw new AuthError(cause.message, 'uri_error', this._state);
    }
  }

  /**
   * Generates a payload message for client credentials.
   *
   * @param {OAuth2Authorization} settings Settings object passed to the `authorize()`
   * function
   * @return {String} Message body as defined in OAuth2 spec.
   */
  _getClientCredentialsBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.clientId || '';
    const cs = settings.clientSecret || cnf.clientSecret;
    const scopes = settings.scopes || this.oauthConfig.scopes;
    const parts = [];
    parts[parts.length] = 'grant_type=client_credentials';
    if (cid) {
      parts[parts.length] = `client_id=${encodeURIComponent(cid)}`;
    }
    if (cs) {
      parts[parts.length] = `client_secret=${encodeURIComponent(cs)}`;
    }
    if (scopes && scopes.length) {
      parts[parts.length] = `scope=${this._computeScope(scopes)}`;
    }
    return parts.join('&');
  }

  /**
   * Performs authorization on custom grant type.
   * This extension is described in OAuth 2.0 spec.
   *
   * @param {OAuth2Authorization} settings Settings object as for `authorize()` function.
   * @return {Promise<TokenInfo>} Promise resolved to a token info object.
   */
  async authorizeCustomGrant(settings) {
    this._settings = settings;
    const url = this._settings.accessTokenUri || this.oauthConfig.accessTokenUri;
    const body = this._getCustomGrantBody(settings);
    try {
      const info = await this._requestToken(url, body, settings);
      this.tokenInfo = info;
      await this.storeToken(info);
      return info;
    } catch (cause) {
      this._handleTokenCodeError(cause);
    }
  }

  /**
   * Creates a body for custom gran type.
   * It does not assume any parameter to be required.
   * It applies all known OAuth 2.0 parameters and then custom parameters
   *
   * @param {OAuth2Authorization} settings Settings object as for `authorize()` function.
   * @return {string} Request body.
   */
  _getCustomGrantBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.clientId || '';
    const cs = settings.clientSecret || cnf.clientSecret;
    const scopes = settings.scopes || this.oauthConfig.scopes;
    let type = settings.responseType || this.oauthConfig.responseType;
    const rUri = settings.redirectUri || this.oauthConfig.redirectUri;
    const parts = [];
    if (type === 'implicit') {
      type = 'token';
    }
    if (type === 'authorization_code') {
      type = 'code';
    }
    parts[parts.length] = `grant_type=${encodeURIComponent(type)}`;
    if (cid) {
      parts[parts.length] = `client_id=${encodeURIComponent(cid)}`;
    }
    if (cs) {
      parts[parts.length] = `client_secret=${encodeURIComponent(cs)}`;
    }
    if (scopes && scopes.length) {
      parts[parts.length] = `scope=${this._computeScope(scopes)}`;
    }
    if (rUri) {
      parts[parts.length] = `redirect_uri=${encodeURIComponent(rUri)}`;
    }
    if (settings.username) {
      parts[parts.length] = `username=${encodeURIComponent(settings.username)}`;
    }
    if (settings.password) {
      parts[parts.length] = `password=${encodeURIComponent(settings.password)}`;
    }
    return parts.join('&');
  }

  /**
   * Creates an error object to be reported back to the app.
   * @param {Object} oauthParams Map of oauth response parameters
   * @return {AuthError} Error object.
   */
  _createResponseError(oauthParams) {
    const code = oauthParams.get('error');
    let message;
    if (oauthParams.has('error_description')) {
      message = oauthParams.get('error_description');
    } else {
      switch (code) {
      case 'interaction_required':
        message = i18n.__('ERR_INTERACTION_REQUIRED');
        break;
      case 'invalid_request':
        message = i18n.__('ERR_INVALID_REQUEST');
        break;
      case 'invalid_client':
        message = i18n.__('ERR_INVALID_CLIENT');
        break;
      case 'invalid_grant':
        message = i18n.__('ERR_INVALID_GRANT');
        break;
      case 'unauthorized_client':
        message = i18n.__('ERR_UNAUTHORIZED_CLIENT');
        break;
      case 'unsupported_grant_type':
        message = i18n.__('ERR_UNSUPPORTED_GRANT_TYPE');
        break;
      case 'invalid_scope':
        message = i18n.__('ERR_INVALID_SCOPE');
        break;
      }
    }
    return new AuthError(message, code, this._state);
  }

  /**
   * Handler for the auth window close event.
   * If the response wasn't reported so far it reports error.
   */
  _authWindowCloseHandler() {
    if (!this.__lastPromise) {
      return;
    }
    this._reportOAuthError(new AuthError(i18n.__('ERR_REQUEST_CANCELLED'), 'user_interrupted', this._state));
  }

  /**
   * A handler for `onComplete` of session's webRequest object.
   * @param {Object} detail
   */
  _sessionCompletedListener(detail) {
    if (detail.resourceType !== 'mainFrame' || !this._oauthWindowListening) {
      return;
    }
    const status = detail.statusCode;
    const url = detail.url;
    const rUri = this._settings.redirectUri || this.oauthConfig.redirectUri;
    if (status >= 400) {
      // This is an error. Redirect URL can be fake and this should catch
      // valid response in 400 status code.
      if (url.indexOf(rUri) !== 0) {
        this._reportOAuthError(new AuthError(i18n.__('ERR_CONFIG_ERROR'), 'uri_error', this._state));
        this.unobserveAuthWindow();
      }
    } else if (url.indexOf(rUri) === 0) {
      if (this.__loadPopupTimeout) {
        clearTimeout(this.__loadPopupTimeout);
      }
      this.unobserveAuthWindow();
      this._reportOAuthResult(url);
    } else if (this._settings.interactive === false) {
      this.__loadPopupTimeout = setTimeout(() => {
        this._reportOAuthError(new AuthError(i18n.__('ERR_SERVER_ERROR'), 'auth_error', this._state));
        this.unobserveAuthWindow();
      }, 1000);
    }
  }

  /**
   * Checks if current token is authorized for given list of scopes.
   *
   * @param {TokenInfo} tokenInfo A token info object.
   * @param {string[]} scopes List of scopes to authorize.
   * @return {Boolean} True if requested scope is already authorized with this
   * token.
   */
  isTokenAuthorized(tokenInfo, scopes) {
    let grantedScopes = tokenInfo.scope;
    if (!grantedScopes || !grantedScopes.length) {
      return true;
    }
    if (!scopes || !scopes.length) {
      return true;
    }
    grantedScopes = grantedScopes.map((scope) => scope.trim());
    scopes = scopes.map((scope) => scope.trim());
    const missing = scopes.find((scope) => grantedScopes.indexOf(scope) === -1);
    return !missing;
  }

  /**
   * Returns cached token info.
   *
   * @return {Promise<TokenInfo>} Token info object or `undefined` if there's
   * no cached token or cached token expired.
   */
  async getTokenInfo() {
    let info;
    if (!this.tokenInfo) {
      info = await this.restoreTokenInfo();
      this.tokenInfo = info;
    } else {
      info = this.tokenInfo;
    }
    if (!info) {
      return;
    }
    if (this.isExpired(info)) {
      this.tokenInfo = undefined;
      return;
    }
    return info;
  }

  /**
   * Restores authorization token information from the local store.
   *
   * @return {Promise<TokenInfo>} Token info object or `undefined` if not set or expired.
   */
  async restoreTokenInfo() {
    if (!this.tokenStore.has(this.cacheKey)) {
      return;
    }
    let data;
    try {
      data = this.tokenStore.get(this.cacheKey);
    } catch (_) {
      // ..
    }
    return /** @type TokenInfo */ (data);
  }

  /**
   * Caches token data in local storage.
   *
   * @param {TokenInfo} tokenInfo
   * @return {Promise<void>} Resolved promise when code is executed
   */
  async storeToken(tokenInfo) {
    this.tokenStore.set(this.cacheKey, tokenInfo);
  }

  /**
   * Checks if the token already expired.
   *
   * @param {TokenInfo} tokenInfo Token info object
   * @return {boolean} True if the token is already expired and should be
   * renewed.
   */
  isExpired(tokenInfo) {
    if (!tokenInfo || !tokenInfo.expiresAt) {
      return true;
    }
    if (Date.now() > tokenInfo.expiresAt) {
      return true;
    }
    return false;
  }

  /**
   * Computes token expiration time.
   * It sets `expires_at` property on the token info object which is the time
   * in the future when when the token expires.
   *
   * @param {TokenInfo} tokenInfo Token info object
   */
  computeExpires(tokenInfo) {
    let expiresIn = tokenInfo.expiresIn;
    if (!expiresIn || Number.isNaN(expiresIn)) {
      expiresIn = 3600;
      tokenInfo.expiresAssumed = true;
    }
    tokenInfo.expiresIn = expiresIn;
    const expiresAt = Date.now() + (expiresIn * 1000);
    tokenInfo.expiresAt = expiresAt;
  }

  /**
   * Generates a random string to be used as a `state` parameter, sets the
   * `_state` property to generated text and returns the value.
   *
   * @return {string} Generated state parameter.
   */
  randomString() {
    let state = '';
    let possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    possible += '0123456789';
    for (let i = 0; i < 6; i++) {
      state += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return state;
  }
}
