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
const {BrowserWindow, session, net} = require('electron');
const {URLSearchParams} = require('url');
const Store = require('electron-store');
// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const windowParams = {
  width: 640,
  height: 800,
  alwaysOnTop: false,
  autoHideMenuBar: true,
  webPreferences: {
    nodeIntegration: false
  }
};
/**
 * A class to perform OAuth2 flow with given configuration.
 *
 * See README.md file for detailed description.
 */
class IdentityProvider {
  /**
   *
   * @param {String} id ID of the provider.
   * @param {?Object} oauthConfig OAuth2 configuration.
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
     * contain all propertiers.
     * This is configuration object used when the OAuth configuration is read
     * from the package.json file.
     * @type {Object}
     */
    this.oauthConfig = oauthConfig || {};
    /**
     * In memory cached token data
     * @type {Object}
     */
    this.tokenInfo = undefined;
    /**
     * Cached token key id in the persistant store.
     * @type {String}
     */
    this.cacheKey = '_oauth_cache_' + this.id;
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
    this.tokentStore = new Store({
      name: 'electron-oauth',
      encryptionKey: 'd622dbf0-a470-4048-95f9-400ef02a2397'
    });
    this._sessionCompletedListener = this._sessionCompletedListener.bind(this);
    this._startSession();
  }

  _startSession() {
    this._session = session.fromPartition('persist:oauth2-win-' + this.id);
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
   * Gets either cached authorization token or request for new one.
   *
   * If the `interactive` flag is false the authorization prompt
   * window will never be opened and if the authorization scope has
   * changed or user did not authorizaed the application this will
   * result in Promise error.
   *
   * @param {Object} opts Authorization options
   * - `interactive` {Boolean} If the interactive flag is `true`, `getAuthToken`
   * will prompt the user as necessary. When the flag is `false` or omitted,
   * `getAuthToken` will return failure any time a prompt would be required.
   * - `scopes` {Array<String>} List of scopes to authorize
   * @return {Promise} A promise resulted to the auth token. It return undefined
   * if the app is not authorized. The promise will result with error (reject)
   * if there's an authorization error.
   */
  getAuthToken(opts) {
    if (!opts) {
      opts = {};
    }
    this._settings = opts;
    return this.getTokenInfo()
    .then((info) => {
      if (info && this.isTokenAuthorized(info, opts.scopes ||
        this.oauthConfig.scopes)) {
        return info;
      }
      this._settings = opts;
      return this.launchWebAuthFlow(opts);
    })
    .catch((cause) => {
      if (opts.interactive === false) {
        return;
      }
      const err = new Error(cause.message);
      err.code = cause.code;
      throw err;
    });
  }
  /**
   * Runs the web authorization flow.
   * @param {Object} opts Authorization options
   * - `interactive` {Boolean} If the interactive flag is `true`,
   * `launchWebAuthFlow` will prompt the user as necessary.
   * When the flag is `false` or omitted, `launchWebAuthFlow`
   * will return failure any time a prompt would be required.
   * - `scopes` {Array<String>} List of scopes to authorize
   * - `login_hint` -  If your application knows which user is trying
   * to authenticate, it can use this parameter to provide
   * a hint to the Authentication Server.
   * The server uses the hint to simplify the login flow either by prefilling
   * the email field in the sign-in form or by selecting the appropriate
   * multi-login session. Set the parameter value to an email address or `sub`
   * identifier.
   * @return {Promise} A promise with auth result.
   */
  launchWebAuthFlow(opts) {
    if (!opts) {
      opts = {};
    }
    this.tokenInfo = undefined;
    this._type = opts.type || opts.response_type || this.oauthConfig.response_type;
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
   * @param {Object} settings Settings passed to the authorize function.
   * @param {String} type `token` or `code`
   * @return {String} Full URL for the endpoint.
   */
  _constructPopupUrl(settings, type) {
    const cnf = this.oauthConfig;
    let url = settings.authorizationUri || cnf.auth_uri;
    if (url.indexOf('?') === -1) {
      url += '?';
    } else {
      url += '&';
    }
    url += 'response_type=' + type + '&';
    const cid = settings.clientId || cnf.client_id || '';
    url += 'client_id=' + encodeURIComponent(cid) + '&';
    const ruri = settings.redirectUri || cnf.redirect_uri;
    if (ruri) {
      url += 'redirect_uri=' + encodeURIComponent(ruri) + '&';
    }
    const scopes = settings.scopes || this.oauthConfig.scopes;
    if (scopes && scopes.length) {
      url += 'scope=' + this._computeScope(scopes);
    }
    url += '&state=' + encodeURIComponent(this._state);
    if (settings.includeGrantedScopes || cnf.include_granted_scopes) {
      url += '&include_granted_scopes=true';
    }
    const lh = settings.loginHint || settings.login_hint;
    if (lh) {
      url += '&login_hint=' + encodeURIComponent(lh);
    }
    if (settings.interactive === false) {
      url += '&prompt=none';
    }
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
   * @param {Array<String>} scopes List of scopes to use with the request.
   * @return {String} Computed scope value.
   */
  _computeScope(scopes) {
    if (!scopes) {
      return '';
    }
    if (typeof scopes === 'string') {
      return scopes;
    }
    if (scopes instanceof Array) {
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
   * @param {String} authUrl Complete authorization url
   * @param {Object} settings Passed user settings
   * @return {Promise}
   */
  _authorize(authUrl, settings) {
    this._settings = settings;
    const params = Object.assign({}, windowParams);
    params.webPreferences.session = this._session;
    if (settings.interactive === false) {
      params.show = false;
    }
    const win = new BrowserWindow(params);
    win.loadURL(authUrl);
    this._observeAuthWindowNavigation(win);
    this.currentOAuthWindow = win;
    return new Promise((resolve, reject) => {
      this.__lastPromise = {
        resolve: resolve,
        reject: reject
      };
    });
  }
  /**
   * Adds listeners to a window object.
   *
   * @param {BrowserWindow} win Window object to observe events on.
   * @param {Boolean} interactive
   */
  _observeAuthWindowNavigation(win) {
    this._oauthWindowListening = true;
    win.on('closed', this._authWindowCloseHandler.bind(this));
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
    win.removeAllListeners('closed');
    win.destroy();
    delete this.currentOAuthWindow;
  }
  /**
   * Reports authorization error back to the application.
   *
   * This operation clears the promise object.
   *
   * @param {Object} details Error details to report to the app.
   * It should contain `code` and `message` properties.
   */
  _reportOAuthError(details) {
    this.unobserveAuthWindow();
    if (!this.__lastPromise) {
      return;
    }
    details.interactive = this._settings.interactive;
    this.__lastPromise.reject(details);
    delete this.__lastPromise;
    this.clear();
  }
  /**
   * Parses response URL and reports the result of the request.
   *
   * @param {Strinig} url Redirected response URL
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
      this._reportOAuthError({
        state: this._state,
        code: 'no_state',
        message: 'Server did not return the state parameter.'
      });
    } else if (state !== this._state) {
      this._reportOAuthError({
        state: this._state,
        code: 'invalid_state',
        message:
          'The state value returned by the authorization server is invalid'
      });
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
   * @return {Object}
   */
  _tokenInfoFromParams(oauthParams) {
    const tokenInfo = {
      access_token: oauthParams.get('access_token'),
      token_type: oauthParams.get('token_type'),
      expires_in: oauthParams.get('expires_in')
    };
    this.computeExpires(tokenInfo);
    Object.keys(tokenInfo).forEach((key) => {
      const camelName = this._camel(key);
      if (camelName) {
        tokenInfo[camelName] = tokenInfo[key];
      }
    });
    let scope = oauthParams.get('scope');
    const requestedScopes = this._settings.scopes || this.oauthConfig.scopes;
    if (scope) {
      scope = scope.split(' ');
      if (requestedScopes) {
        scope = requestedScopes.concat(scope);
      }
    } else if (requestedScopes) {
      scope = requestedScopes;
    }
    tokenInfo.scope = scope;
    return tokenInfo;
  }
  /**
   * Resolves the main promise with token data.
   * @param {Object} info Auth token information
   */
  _handleTokenInfo(info) {
    this.tokenInfo = info;
    this.storeToken(info);
    if (!this.__lastPromise) {
      console.error('Promise is already resolved');
      return;
    }
    info.interactive = this._settings.interactive;
    this.__lastPromise.resolve(Object.assign({}, info));
    delete this.__lastPromise;
    this.clear();
  }
  /**
   * Handler fore an error that happened during code exchange.
   * @param {Error} e
   */
  _handleTokenCodeError(e) {
    console.error(e);
    this._reportOAuthError({
      state: this._state,
      code: 'uri_error',
      message: e.message
    });
  }
  /**
   * Exchange code for token.
   *
   * @param {String} code Returned code from the authorization endpoint.
   * @return {Promise}
   */
  _exchangeCode(code) {
    const url = this._settings.accessTokenUri || this._settings.token_uri ||
      this.oauthConfig.token_uri;
    const body = this._getCodeEchangeBody(this._settings, code);
    return this._requestToken(url, body, this._settings)
    .then((tokenInfo) => this._handleTokenInfo(tokenInfo))
    .catch((cause) => this._handleTokenCodeError(cause));
  }
  /**
   * Returns a body value for the code exchange request.
   * @param {Object} settings Initial settings object.
   * @param {String} code Authorization code value returned by the authorization
   * server.
   * @return {String} Request body.
   */
  _getCodeEchangeBody(settings, code) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.client_id || '';
    const ruri = settings.redirectUri || cnf.redirect_uri;
    const cs = settings.clientSecret || cnf.client_secret;
    let url = 'grant_type=authorization_code';
    url += '&client_id=' + encodeURIComponent(cid);
    if (ruri) {
      url += '&redirect_uri=' + encodeURIComponent(ruri);
    }
    url += '&code=' + encodeURIComponent(code);
    if (cs) {
      url += '&client_secret=' + encodeURIComponent(cs);
    } else {
      url += '&client_secret=';
    }
    return url;
  }
  /**
   * Camel case given name.
   *
   * @param {String} name Value to camel case.
   * @return {String} Camel cased name
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
   * @param {String} url Base URI of the endpoint. Custom properties will be
   * applied to the final URL.
   * @param {String} body Generated body for given type. Custom properties will
   * be applied to the final body.
   * @param {Object} settings Settings object passed to the `authorize()` function
   * @return {Promise} Promise resolved to the response string.
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
        url
      });
      request.setHeader('Content-Type', 'application/x-www-form-urlencoded');
      if (settings.customData) {
        this._applyCustomSettingsHeaders(request, settings.customData);
      }
      request.on('response', (response) => {
        const ro = {
          status: response.statusCode,
          headers: response.headers,
          body: ''
        };
        response.on('data', (chunk) => {
          ro.body += chunk;
        });
        response.on('end', () => this._processTokenResponseHandler(ro, resolve, reject));
        request.on('error', (error) => this._processTokenResponseErrorHandler(error, reject));
      });
      request.on('error', (error) => this._processTokenResponseErrorHandler(error, reject));
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
    let message = 'The request to the authorization server failed.';
    if (error && error.message) {
      console.error(error);
      message += ' ' + error.message;
    }
    reject(new Error(message));
  }
  /**
   * Handler for the code request load event.
   * Processes the response and either rejects the promise with an error
   * or resolves it to token info object.
   *
   * @param {Object} response A response containing `status` and `body  `
   * @param {Function} resolve Resolve function
   * @param {Function} reject Reject function
   */
  _processTokenResponseHandler(response, resolve, reject) {
    const status = response.status;
    const srvResponse = response.body;
    if (status === 404) {
      let message = 'Authorization URI is invalid. Received status 404.';
      reject(new Error(message));
      return;
    } else if (status >= 400 && status < 500) {
      let message = 'Client error: ' + srvResponse;
      reject(new Error(message));
      return;
    } else if (status >= 500) {
      let message = 'Authorization server error. Response code is ' + status;
      reject(new Error(message));
      return;
    }
    let tokenInfo;
    try {
      tokenInfo = this._processCodeResponse(srvResponse,
        response.headers['content-type']);
    } catch (e) {
      reject(new Error(e.message));
      return;
    }
    resolve(tokenInfo);
  }
  /**
   * Processes token request body and produces map of values.
   *
   * @param {String} body Body received in the response.
   * @param {String} contentType Response content type.
   * @return {Object} Response as an object.
   * @throws {Error} Exception when body is invalid.
   */
  _processCodeResponse(body, contentType) {
    if (!body) {
      throw new Error('Code response body is empty.');
    }
    if (contentType instanceof Array) {
      contentType = contentType[0];
    }
    let tokenInfo;
    if (contentType.indexOf('json') !== -1) {
      tokenInfo = JSON.parse(body);
      for (let name in tokenInfo) {
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
   * @param {String} url Generated URL for an endpoint.
   * @param {?Object} data `customData.[type]` property from the settings object.
   * The type is either `auth` or `token`.
   * @return {String}
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
      return encodeURIComponent(item.name) + '=' + value;
    }).join('&');
    return url;
  }
  /**
   * Applies custom headers from the settings object
   *
   * @param {net.request} request Instance of the request object.
   * @param {Object} data Value of settings' `customData` property
   */
  _applyCustomSettingsHeaders(request, data) {
    if (!data || !data.token || !data.token.headers) {
      return;
    }
    data.token.headers.forEach((item) => {
      try {
        request.setHeader(item.name, item.value);
      } catch (e) {
        console.warn('Unable to set custom header value.');
      }
    });
  }
  /**
   * Applies custom body properties from the settings to the body value.
   *
   * @param {String} body Already computed body for OAuth request. Custom
   * properties are appended at the end of OAuth string.
   * @param {Object} data Value of settings' `customData` property
   * @return {String} Request body
   */
  _applyCustomSettingsBody(body, data) {
    if (!data || !data.token || !data.token.body) {
      return body;
    }
    body += '&' + data.token.body.map(function(item) {
      let value = item.value;
      if (value) {
        value = encodeURIComponent(value);
      } else {
        value = '';
      }
      return encodeURIComponent(item.name) + '=' + value;
    }).join('&');
    return body;
  }
  /**
   * Requests a token for `password` request type.
   *
   * @param {Object} settings The same settings as passed to `authorize()`
   * function.
   * @return {Promise} Promise resolved to token info.
   */
  authorizePassword(settings) {
    this._settings = settings;
    const url = settings.accessTokenUri || settings.token_uri ||
      this.oauthConfig.token_uri;
    const body = this._getPasswordBody(settings);
    return this._requestToken(url, body, settings)
    .then((info) => {
      this.tokenInfo = info;
      return this.storeToken(info)
      .then(() => info);
    })
    .catch((cause) => {
      const obj = {
        state: this._state,
        code: 'uri_error',
        message: cause.message
      };
      throw obj;
    });
  }
  /**
   * Generates a payload message for password authorization.
   *
   * @param {Object} settings Settings object passed to the `authorize()`
   * function
   * @return {String} Message body as defined in OAuth2 spec.
   */
  _getPasswordBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.client_id || '';
    const scopes = settings.scopes || this.oauthConfig.scopes;
    let url = 'grant_type=password';
    url += '&username=' + encodeURIComponent(settings.username);
    url += '&password=' + encodeURIComponent(settings.password);
    if (cid) {
      url += '&client_id=' + encodeURIComponent(cid);
    }
    if (scopes && scopes.length) {
      url += '&scope=' + this._computeScope(scopes);
    }
    return url;
  }
  /**
   * Requests a token for `client_credentials` request type.
   *
   * @param {Object} settings The same settings as passed to `authorize()`
   * function.
   * @return {Promise} Promise resolved to a token info object.
   */
  authorizeClientCredentials(settings) {
    this._settings = settings;
    const url = this._settings.accessTokenUri || this._settings.token_uri ||
      this.oauthConfig.token_uri;
    const body = this._getClientCredentialsBody(settings);
    return this._requestToken(url, body, settings)
    .then((info) => {
      this.tokenInfo = info;
      return this.storeToken(info)
      .then(() => info);
    })
    .catch((cause) => {
      const obj = {
        state: this._state,
        code: 'uri_error',
        message: cause.message
      };
      throw obj;
    });
  }
  /**
   * Generates a payload message for client credentials.
   *
   * @param {Object} settings Settings object passed to the `authorize()`
   * function
   * @return {String} Message body as defined in OAuth2 spec.
   */
  _getClientCredentialsBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.client_id || '';
    const cs = settings.clientSecret || cnf.client_secret;
    const scopes = settings.scopes || this.oauthConfig.scopes;
    let url = 'grant_type=client_credentials';
    if (cid) {
      url += '&client_id=' + encodeURIComponent(cid);
    }
    if (cs) {
      url += '&client_secret=' + encodeURIComponent(cs);
    }
    if (scopes && scopes.length) {
      url += '&scope=' + this._computeScope(scopes);
    }
    return url;
  }
  /**
   * Performs authorization on custom grant type.
   * This extension is described in OAuth 2.0 spec.
   *
   * @param {Object} settings Settings object as for `authorize()` function.
   * @return {Promise} Promise resolved to a token info object.
   */
  authorizeCustomGrant(settings) {
    this._settings = settings;
    const url = this._settings.accessTokenUri || this._settings.token_uri ||
      this.oauthConfig.token_uri;
    const body = this._getCustomGrantBody(settings);
    return this._requestToken(url, body, settings)
    .then((tokenInfo) => this._handleTokenInfo(tokenInfo))
    .catch((cause) => this._handleTokenCodeError(cause));
  }
  /**
   * Creates a body for custom gran type.
   * It does not assume any parameter to be required.
   * It applies all known OAuth 2.0 parameters and then custom parameters
   *
   * @param {Object} settings
   * @return {String} Request body.
   */
  _getCustomGrantBody(settings) {
    const cnf = this.oauthConfig;
    const cid = settings.clientId || cnf.client_id || '';
    const cs = settings.clientSecret || cnf.client_secret;
    const scopes = settings.scopes || this.oauthConfig.scopes;
    let type = settings.type || settings.response_type || this.oauthConfig.response_type;
    const ruri = settings.redirectUri || this.oauthConfig.redirect_uri;
    if (type === 'implicit') {
      type = 'token';
    }
    if (type === 'authorization_code') {
      type = 'code';
    }
    let url = 'grant_type=' + encodeURIComponent(type);
    if (cid) {
      url += '&client_id=' + encodeURIComponent(cid);
    }
    if (cs) {
      url += '&client_secret=' + encodeURIComponent(cs);
    }
    if (scopes && scopes.length) {
      url += '&scope=' + this._computeScope(scopes);
    }
    if (ruri) {
      url += '&redirect_uri=' + encodeURIComponent(ruri);
    }
    if (settings.username) {
      url += '&username=' + encodeURIComponent(settings.username);
    }
    if (settings.password) {
      url += '&password=' + encodeURIComponent(settings.password);
    }
    return url;
  }
  /**
   * Creates an error object to be reported back to the app.
   * @param {Object} oauthParams Map of oauth response parameteres
   * @return {Object} Error message:
   * - code {String} - The `error` property returned by the server.
   * - message {String} - Error message returned by the server.
   */
  _createResponseError(oauthParams) {
    const detail = {
      state: this._state,
      code: oauthParams.get('error')
    };
    let message;
    if (oauthParams.has('error_description')) {
      message = oauthParams.get('error_description');
    } else {
      switch (detail.code) {
        case 'interaction_required':
          message = 'The request requires user interaction.';
          break;
        case 'invalid_request':
          message = 'The request is missing a required parameter.';
          break;
        case 'invalid_client':
          message = 'Client authentication failed.';
          break;
        case 'invalid_grant':
          message = 'The provided authorization grant or refresh token is';
          message += ' invalid, expired, revoked, does not match the ';
          message += 'redirection URI used in the authorization request, ';
          message += 'or was issued to another client.';
          break;
        case 'unauthorized_client':
          message = 'The authenticated client is not authorized to use this';
          message += ' authorization grant type.';
          break;
        case 'unsupported_grant_type':
          message = 'The authorization grant type is not supported by the';
          message += ' authorization server.';
          break;
        case 'invalid_scope':
          message = 'The requested scope is invalid, unknown, malformed, or';
          message += ' exceeds the scope granted by the resource owner.';
          break;
      }
    }
    detail.message = message;
    return detail;
  }
  /**
   * Handler for the auth window close event.
   * If the response wasn't reported so far it reports error.
   */
  _authWindowCloseHandler() {
    if (this.__lastPromise) {
      this._reportOAuthError({
        state: this._state,
        code: 'user_interrupted',
        message: 'The request has been canceled by the user.'
      });
    }
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
    const ruri = this._settings.redirectUri || this.oauthConfig.redirect_uri;
    if (status >= 400) {
      // This is an error. Redirect URL can be fake and this should catch
      // valid response in 400 status code.
      if (url.indexOf(ruri) !== 0) {
        let msg = 'Unable to run authorization flow. Make sure the OAuth2 ';
        msg += 'config is valid.';
        this._reportOAuthError({
          state: this._state,
          code: 'uri_error',
          message: msg
        });
        this.unobserveAuthWindow();
      }
    } else if (url.indexOf(ruri) === 0) {
      if (this.__loadPopupTimeout) {
        clearTimeout(this.__loadPopupTimeout);
      }
      this.unobserveAuthWindow();
      this._reportOAuthResult(url);
    } else {
      if (this._settings.interactive === false) {
        this.__loadPopupTimeout = setTimeout(() => {
          this._reportOAuthError({
            state: this._state,
            code: 'auth_error',
            message:
              'No response from the server.'
          });
          this.unobserveAuthWindow();
        }, 1000);
      }
    }
  }
  /**
   * Computes `scope` URL parameter from scopes array.
   *
   * @param {Array<String>} scopes List of scopes to use with the request.
   * @return {String} Computed scope value.
   */
  computeScope(scopes) {
    if (!scopes) {
      return '';
    }
    let scope = scopes.join(' ');
    return encodeURIComponent(scope);
  }
  /**
   * Checks if current token is authorized for given list of scopes.
   *
   * @param {Object} tokenInfo A token info object.
   * @param {Array<String>} scopes List of scopes to authorize.
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
    let missing = scopes.find((scope) => {
      return grantedScopes.indexOf(scope) === -1;
    });
    return !missing;
  }

  /**
   * Returns cached token info.
   *
   * @return {Object} Token info ibject or undefined if there's no cached token
   * or cached token expired.
   */
  getTokenInfo() {
    let promise;
    if (!this.tokenInfo) {
      promise = this.restoreTokenInfo();
    } else {
      promise = Promise.resolve(this.tokenInfo);
    }
    return promise
    .then((info) => {
      this.tokenInfo = info;
      if (!this.tokenInfo) {
        return;
      }
      if (this.isExpired(this.tokenInfo)) {
        this.tokenInfo = undefined;
        return;
      }
      return this.tokenInfo;
    });
  }
  /**
   * Restores authorization token information from the local store.
   *
   * @return {Object} Token info object or undefined if not set or expired.
   */
  restoreTokenInfo() {
    if (!this.tokentStore.has(this.cacheKey)) {
      return Promise.resolve();
    }
    let data;
    try {
      data = this.tokentStore.get(this.cacheKey);
    } catch (_) {}
    return Promise.resolve(data);
  }
  /**
   * Casches token data in local storage.
   *
   * @param {Object} tokenInfo
   * @return {Promise} Resolved promise when code is executed
   */
  storeToken(tokenInfo) {
    this.tokentStore.set(this.cacheKey, tokenInfo);
    return Promise.resolve();
  }
  /**
   * Checks if the token already expired.
   *
   * @param {Object} tokenInfo Token info object
   * @return {Boolean} True if the token is already expired and should be
   * reneved.
   */
  isExpired(tokenInfo) {
    if (!tokenInfo || !tokenInfo.expires_at) {
      return true;
    }
    if (Date.now() > tokenInfo.expires_at) {
      return true;
    }
    return false;
  }
  /**
   * Computes token expiration time.
   * It sets `expires_at` property on the token info object which is the time
   * in the future when when the token expires.
   *
   * @param {Object} tokenInfo Token info object
   */
  computeExpires(tokenInfo) {
    let expiresIn = tokenInfo.expires_in;
    if (!expiresIn) {
      expiresIn = 3600;
      tokenInfo.expiresAssumed = true;
    }
    if (typeof expiresIn !== 'number') {
      expiresIn = Number(expiresIn);
      if (expiresIn !== expiresIn) {
        expiresIn = 3600;
        tokenInfo.expiresAssumed = true;
      }
    }
    tokenInfo.expires_in = expiresIn;
    expiresIn = Date.now() + (expiresIn * 1000);
    tokenInfo.expires_at = expiresIn;
    tokenInfo.expiresAt = expiresIn;
  }
  /**
   * Generates a random string to be used as a `state` parameter, sets the
   * `_state` property to generated text and returns the value.
   *
   * @return {String} Generated state parameter.
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

exports.IdentityProvider = IdentityProvider;
