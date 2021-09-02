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
import { AuthorizationError, CodeError } from './AuthorizationError.js';
import { applyCustomSettingsQuery, applyCustomSettingsBody, applyCustomSettingsHeaders } from './CustomParameters.js';
import { sanityCheck, randomString, camel, generateCodeChallenge } from './Utils.js';
// eslint-disable-next-line import/no-namespace
import * as KnownGrants from './KnownGrants.js';

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

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenInfo} TokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2CustomData} OAuth2CustomData */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2AuthorizationRequestCustomData} OAuth2AuthorizationRequestCustomData */
/** @typedef {import('../types').FetchResponse} FetchResponse */

export const authorize = Symbol('authorize');
export const reportOAuthError = Symbol('reportOAuthError');
export const authorizeImplicitCode = Symbol('authorizeImplicitCode');
export const authWindowCloseHandler = Symbol('authWindowCloseHandler');
export const observeAuthWindowNavigation = Symbol('observeAuthWindowNavigation');
export const sessionErrorListener = Symbol('sessionErrorListener');
export const sessionCompletedListener = Symbol('sessionCompletedListener');
export const processPopupRawData = Symbol('processPopupRawData');
export const createErrorParams = Symbol('createErrorParams');
export const handleTokenInfo = Symbol('handleTokenInfo');
export const tokenResponse = Symbol('tokenResponse');
export const computeTokenInfoScopes = Symbol('computeTokenInfoScopes');
export const computeExpires = Symbol('computeExpires');
export const handleTokenCodeError = Symbol('handleTokenCodeError');
export const authorizeClientCredentials = Symbol('authorizeClientCredentials');
export const authorizePassword = Symbol('authorizePassword');
export const authorizeCustomGrant = Symbol('authorizeCustomGrant');
export const authorizeDeviceCode = Symbol('authorizeDeviceCode');
export const authorizeJwt = Symbol('authorizeJwt');
export const startSession = Symbol('startSession');
export const resolveFunction = Symbol('resolveFunction');
export const rejectFunction = Symbol('rejectFunction');
export const tokenInfoFromParams = Symbol('tokenInfoFromParams');
export const stateValue = Symbol('stateValue');
export const settingsValue = Symbol('settingsValue');

export const grantResponseMapping = {
  implicit: 'token',
  authorization_code: 'code',
};

/**
 * A class to perform OAuth2 flow with given configuration.
 *
 * See README.md file for detailed description.
 */
export class IdentityProvider {
  /**
   * @return {OAuth2Authorization} The authorization settings used to initialize this class.
   */
  get settings() {
    return this[settingsValue];
  }

  /**
   * The code verifier used by the PKCE extension
   * @type string;
   */
  #codeVerifier;

  /**
   * Instance of the store library to cache token data.
   * @type {Store}
   */
  tokenStore = new Store({
    name: 'electron-oauth',
    encryptionKey: 'd622dbf0-a470-4048-95f9-400ef02a2397',
  });

  #oauthWindowListening = false;

  /**
   * @type {NodeJS.Timeout}
   */
  #loadPopupTimeout;

  /**
   * @type Electron.Session
   */
  #session;

  /**
   * @return {string} The request state parameter. If the state is not passed with the configuration one is generated.
   */
  get state() {
    if (!this[stateValue]) {
      this[stateValue] = this[settingsValue].state || randomString();
    }
    return this[stateValue];
  }

  /**
   * When PKCE extension is used, this holds the value of generated code verifier
   */
  get codeVerifier() {
    return this.#codeVerifier;
  }

  /**
   *
   * @param {string} id ID of the provider.
   * @param {OAuth2Authorization=} oauthConfig OAuth2 configuration.
   */
  constructor(id, oauthConfig={}) {
    /**
     * Generated ID for the provider.
     *
     * @type {string}
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
    this.oauthConfig = oauthConfig;
    /**
     * The final OAuth 2 settings to use.
     * @type {OAuth2Authorization}
     */
    this[settingsValue] = oauthConfig;

    /**
     * The current state parameter
     * @type string;
     */
    this[stateValue] = undefined;

    /**
     * Cached token key id in the persistent store.
     * @type {String}
     */
    this.cacheKey = `_oauth_cache_${this.id}`;
    this[sessionCompletedListener] = this[sessionCompletedListener].bind(this);
    this[sessionErrorListener] = this[sessionErrorListener].bind(this);
    this[authWindowCloseHandler] = this[authWindowCloseHandler].bind(this);
    this[startSession]();
    /**
     * The user agent to be set on the browser window when requesting for a token
     * in a browser flow. This allows to fix the issue with Google auth servers that
     * stopped supporting default electron user agent.
     */
    this.userAgent = 'Chrome';

    /**
     * @type {(info: TokenInfo) => void} The main resolve function
     */
    this[resolveFunction] = undefined;

    /**
     * @type {(error: Error) => void} The main reject function
     */
    this[rejectFunction] = undefined;
  }

  /**
   * Enables session in module's partition.
   */
  [startSession]() {
    this.#session = session.fromPartition(`persist:oauth2-win-${this.id}`);
    this.#session.webRequest.onCompleted(this[sessionCompletedListener]);
    this.#session.webRequest.onErrorOccurred(this[sessionErrorListener]);
  }

  /**
   * Clears the state of the element.
   */
  clear() {
    this[stateValue] = undefined;
    this[settingsValue] = undefined;
    this.unobserveAuthWindow();
  }

  /**
   * Clears token cache data and current token information.
   */
  clearCache() {
    if (this.tokenStore.has(this.cacheKey)) {
      this.tokenStore.delete(this.cacheKey);
    }
  }

  /**
   * A function that should be called before the authorization.
   * It checks configuration integrity, and performs some sanity checks
   * like proper values of the request URIs.
   */
  checkConfig() {
    // @todo(pawel): perform settings integrity tests.
    sanityCheck(this[settingsValue]);
  }

  /**
   * Gets either cached authorization token or request for new one.
   *
   * If the `interactive` flag is false the authorization prompt
   * window will never be opened and if the authorization scope has
   * changed or user did not authorized the application this will
   * result in Promise error.
   *
   * @param {OAuth2Authorization=} settings Authorization options
   * @return {Promise<TokenInfo>} A promise resulted to the auth token.
   * It return undefined if the app is not authorized. The promise will result
   * with error (reject) if there's an authorization error.
   */
  async getAuthToken(settings={}) {
    this[settingsValue] = { ...this.oauthConfig, ...settings };
    this.checkConfig();
    try {
      const info = await this.getTokenInfo();
      const scopes = settings.scopes || this.oauthConfig.scopes;
      if (info && this.isTokenAuthorized(info, scopes)) {
        delete info.state;
        if (settings.state) {
          info.state = settings.state;
        }
        return info;
      }
      return await this.launchWebAuthFlow(settings);
    } catch (cause) {
      if (settings.interactive === false) {
        return;
      }
      const err = new AuthorizationError(cause.message, cause.code, settings.state, false);
      throw err;
    }
  }

  /**
   * Runs the web authorization flow.
   * @param {OAuth2Authorization=} settings Authorization options
   * @return {Promise<TokenInfo>} A promise with auth result.
   */
  launchWebAuthFlow(settings={}) {
    this[settingsValue] = { ...this.oauthConfig, ...settings };
    this.checkConfig();
    return new Promise((resolve, reject) => {
      this[resolveFunction] = resolve;
      this[rejectFunction] = reject;
      this[authorize]();
    });
  }

  /**
   * Starts the authorization process.
   */
  [authorize]() {
    const settings = this[settingsValue];
    switch (settings.grantType) {
      case KnownGrants.implicit:
      case KnownGrants.code:
        this[authorizeImplicitCode]();
        break;
      case KnownGrants.clientCredentials:
        this[authorizeClientCredentials]();
        break;
      case KnownGrants.password:
        this[authorizePassword]();
        break;
      case KnownGrants.deviceCode:
        this[authorizeDeviceCode]();
        break;
      case KnownGrants.jwtBearer:
        this[authorizeJwt]();
        break;
      default:
        this[authorizeCustomGrant]();
    }
  }

  /**
   * Starts the authorization flow for the `implicit` and `authorization_code` flows.
   * If the `interactive` flag is configured, then it won't show the window.
   */
  async [authorizeImplicitCode]() {
    try {
      const url = await this.constructPopupUrl();
      const params = { ...windowParams };
      params.webPreferences.session = this.#session;
      if (this[settingsValue].interactive === false) {
        params.show = false;
      }
      const win = new BrowserWindow(params);
      win.loadURL(url, { userAgent: this.userAgent });
      this[observeAuthWindowNavigation](win);
      this.currentOAuthWindow = win;
    } catch (e) {
      this[reportOAuthError]('Unable to initialize the OAuth flow', 'internal_error');
    }
  }

  /**
   * Browser or server flow: open the initial popup.
   * @return {Promise<string>} Full URL for the endpoint.
   */
  async constructPopupUrl() {
    const url = await this.buildPopupUrlParams();
    return url.toString();
  }

  /**
   * @return {Promise<URL>} The parameters to build popup URL.
   */
  async buildPopupUrlParams() {
    const settings = this[settingsValue];
    const type = /** @type string */ (settings.responseType || grantResponseMapping[settings.grantType]);
    if (!type) {
      throw new Error(`Invalid grant type`);
    }
    const url = new URL(settings.authorizationUri);
    url.searchParams.set('response_type', type);
    url.searchParams.set('client_id', settings.clientId);
    // Client secret cannot be ever exposed to the client (browser)!
    // if (settings.clientSecret) {
    //   url.searchParams.set('client_secret', settings.clientSecret);
    // }
    url.searchParams.set('state', this.state);
    if (settings.redirectUri) {
      url.searchParams.set('redirect_uri', settings.redirectUri);
    }
    const { scopes } = settings;
    if (Array.isArray(scopes) && scopes.length) {
      url.searchParams.set('scope', scopes.join(' '));
    }
    if (settings.includeGrantedScopes) {
      // this is Google specific
      url.searchParams.set('include_granted_scopes', 'true');
    }
    if (settings.loginHint) {
      // this is Google specific
      url.searchParams.set('login_hint', settings.loginHint);
    }
    if (settings.interactive === false) {
      // this is Google specific
      url.searchParams.set('prompt', 'none');
    }
    if (settings.pkce && type === 'code') {
      this.#codeVerifier = randomString();
      const challenge = await generateCodeChallenge(this.#codeVerifier);
      url.searchParams.set('code_challenge', challenge);
      url.searchParams.set('code_challenge_method', 'S256');
    }
    // custom query parameters from the `api-authorization-method` component
    if (settings.customData) {
      const cs = settings.customData.auth;
      if (cs) {
        applyCustomSettingsQuery(url, cs);
      }
    }
    return url;
  }

  /**
   * Adds listeners to a window object.
   *
   * @param {BrowserWindow} win Window object to observe events on.
   */
  [observeAuthWindowNavigation](win) {
    this.#oauthWindowListening = true;
    win.on('closed', this[authWindowCloseHandler]);
  }

  /**
   * Removes event listeners, closes the window and cleans the property.
   */
  unobserveAuthWindow() {
    this.#oauthWindowListening = false;
    const win = this.currentOAuthWindow;
    if (!win) {
      return;
    }
    win.removeListener('closed', this[authWindowCloseHandler]);
    win.destroy();
    delete this.currentOAuthWindow;
  }

  /**
   * Handler for the auth window close event.
   * If the response wasn't reported so far it reports error.
   */
  [authWindowCloseHandler]() {
    if (!this[rejectFunction]) {
      return;
    }
    this[reportOAuthError](i18n.__('ERR_REQUEST_CANCELLED'), 'user_interrupted');
  }

  /**
   * Reports authorization error back to the application.
   *
   * This operation clears the promise object.
   *
   * @param {string} message The message to report
   * @param {string} code Error code
   */
  [reportOAuthError](message, code) {
    this.unobserveAuthWindow();
    if (!this[rejectFunction]) {
      return;
    }
    const interactive = typeof this[settingsValue].interactive === 'boolean' ? this[settingsValue].interactive : true;
    const e = new AuthorizationError(
      message,
      code,
      this.state,
      interactive,
    );
    this[rejectFunction](e);
    this[rejectFunction] = undefined;
    this[resolveFunction] = undefined;
  }

  /**
   * Parses response URL and reports the result of the request.
   *
   * @param {string} url Redirected response URL
   */
  [processPopupRawData](url) {
    this.unobserveAuthWindow();
    if (!url) {
      return;
    }
    /** @type URLSearchParams */
    let params;
    try {
      const parsed = new URL(url);
      const { search, hash } = parsed;
      const paramsString = search ? search.substr(1) : hash.substr(1);
      params = new URLSearchParams(paramsString);
    } catch (e) {
      this[reportOAuthError](i18n.__('ERR_INVALID_URL_DATA'), 'invalid_url_data');
      return;
    }
    if (this.validateTokenResponse(params)) {
      this.processTokenResponse(params);
    } else {
      // eslint-disable-next-line no-console
      console.warn('Unprocessable authorization response', url);
    }
  }

  /**
   * @param {URLSearchParams} params The instance of search params with the response from the auth dialog.
   * @return {boolean} true when the params qualify as an authorization popup redirect response.
   */
  validateTokenResponse(params) {
    const oauthParams = [
      'state',
      'error',
      'access_token',
      'code',
    ];
    return oauthParams.some((name) => params.has(name));
  }

  /**
   * Processes OAuth2 server query string response.
   *
   * @param {URLSearchParams} oauthParams Created from parameters params.
   */
  async processTokenResponse(oauthParams) {
    const state = oauthParams.get('state');
    if (!state) {
      this[reportOAuthError](i18n.__('ERR_SERVER_STATE'), 'no_state');
      return;
    }
    if (state !== this.state) {
      this[reportOAuthError](i18n.__('ERR_STATE_MISMATCH'), 'invalid_state');
      return;
    }
    if (oauthParams.has('error')) {
      this[reportOAuthError](...this.createTokenResponseError(oauthParams));
      return;
    }
    const { grantType, responseType } = this[settingsValue];
    if (grantType === 'implicit' || responseType === 'id_token') {
      this[handleTokenInfo](this[tokenInfoFromParams](oauthParams));
      return;
    }
    if (grantType === 'authorization_code') {
      const code = oauthParams.get('code');
      if (!code) {
        this[reportOAuthError](i18n.__('ERR_NO_CODE'), 'no_code');
        return;
      }
      let tokenInfo;
      try {
        tokenInfo = await this.exchangeCode(code);
      } catch (e) {
        this[handleTokenCodeError](e);
        return;
      }
      this[handleTokenInfo](tokenInfo);
      return;
    }
    this[reportOAuthError](i18n.__('ERR_UNKNOWN_STATE'), 'unknown_state');
  }

  /**
   * Creates a token info object from query parameters
   * @param {URLSearchParams} oauthParams
   * @return {TokenInfo}
   */
  [tokenInfoFromParams](oauthParams) {
    const accessToken = oauthParams.get('access_token');
    const idToken = oauthParams.get('id_token');
    const refreshToken = oauthParams.get('refresh_token');
    const tokenType = oauthParams.get('token_type');
    const expiresIn = Number(oauthParams.get('expires_in'));
    const scope = this[computeTokenInfoScopes](oauthParams.get('scope'));
    const tokenInfo = /** @type TokenInfo */ ({
      accessToken,
      idToken,
      refreshToken,
      tokenType,
      expiresIn,
      state: oauthParams.get('state'),
      scope,
      expiresAt: undefined,
      expiresAssumed: false,
      interactive: this[settingsValue].interactive,
    });
    return this[computeExpires](tokenInfo);
  }

  /**
   * Computes the final list of granted scopes.
   * It is a list of scopes received in the response or the list of requested scopes.
   * Because the user may change the list of scopes during the authorization process
   * the received list of scopes can be different than the one requested by the user.
   *
   * @param {string} scope The `scope` parameter received with the response. It's null safe.
   * @return {string[]} The list of scopes for the token.
   */
  [computeTokenInfoScopes](scope) {
    const requestedScopes = this[settingsValue].scopes;
    if (!scope && requestedScopes) {
      return requestedScopes;
    }
    let listScopes = [];
    if (scope) {
      listScopes = scope.split(' ');
    }
    return listScopes;
  }

  /**
   * Computes token expiration time.
   * It sets `expires_at` property on the token info object which is the time
   * in the future when when the token expires.
   *
   * @param {TokenInfo} tokenInfo Token info object
   * @return {TokenInfo} A copy with updated properties.
   */
  [computeExpires](tokenInfo) {
    const copy = { ...tokenInfo };
    let { expiresIn } = copy;
    if (!expiresIn || Number.isNaN(expiresIn)) {
      expiresIn = 3600;
      copy.expiresAssumed = true;
    }
    copy.expiresIn = expiresIn;
    const expiresAt = Date.now() + (expiresIn * 1000);
    copy.expiresAt = expiresAt;
    return copy;
  }

  /**
   * Processes token info object when it's ready.
   *
   * @param {TokenInfo} info Token info returned from the server.
   */
  [handleTokenInfo](info) {
    // validate the token
    if (!info || !info.accessToken) {
      this[reportOAuthError](i18n.__('ERR_SERVER_ERROR'), 'auth_error');
      return;
    }

    this[tokenResponse] = info;
    this.storeToken(info);
    if (this[resolveFunction]) {
      this[resolveFunction](info);
    }
    this[resolveFunction] = undefined;
    this[rejectFunction] = undefined;
    this.clear();
  }

  /**
   * Exchanges the authorization code for authorization token.
   *
   * @param {string} code Returned code from the authorization endpoint.
   * @return {Promise<Record<string, any>>} The response from the server.
   */
  async getCodeInfo(code) {
    const body = this.getCodeRequestBody(code);
    const url = this[settingsValue].accessTokenUri;
    return this.requestTokenInfo(url, body);
  }

  /**
   * Requests for token from the authorization server for `code`, `password`, `client_credentials` and custom grant types.
   *
   * @param {string} url Base URI of the endpoint. Custom properties will be applied to the final URL.
   * @param {string} body Generated body for given type. Custom properties will be applied to the final body.
   * @param {Record<string, string>=} optHeaders Optional headers to add to the request. Applied after custom data.
   * @return {Promise<Record<string, any>>} Promise resolved to the response string.
   */
  async requestTokenInfo(url, body, optHeaders) {
    const urlInstance = new URL(url);
    const settings = this[settingsValue];
    let headers = /** @type Record<string, string> */ ({
      'content-type': 'application/x-www-form-urlencoded',
    });
    if (settings.customData) {
      if (settings.customData.token) {
        applyCustomSettingsQuery(urlInstance, settings.customData.token);
      }
      body = applyCustomSettingsBody(body, settings.customData);
      headers = applyCustomSettingsHeaders(headers, settings.customData);
    }
    if (optHeaders) {
      headers = { ...headers, ...optHeaders };
    }
    const authTokenUrl = urlInstance.toString();
    const response = await this.fetchToken(authTokenUrl, headers, body);
    const { status } = response;
    if (status === 404) {
      throw new Error(i18n.__('ERR_CODE_404'));
    }
    if (status >= 500) {
      throw new Error(i18n.__(`Authorization server error. Response code is %s`, String(status)));
    }
    let responseBody = response.body;
    if (!responseBody) {
      responseBody = 'No response has been recorded';
    }
    if (status >= 400 && status < 500) {
      throw new Error(i18n.__(`Client error: %s`, responseBody));
    }
    let mime = response.headers['content-type'];
    if (Array.isArray(mime)) {
      [mime] = mime;
    }
    return this.processCodeResponse(responseBody, mime);
  }

  /**
   * Processes body of the code exchange to a map of key value pairs.
   * @param {string} body
   * @param {string} mime
   * @return {Record<string, any>}
   */
  processCodeResponse(body, mime='') {
    let tokenInfo = /** @type Record<string, any> */ ({});
    if (mime.includes('json')) {
      const info = JSON.parse(body);
      Object.keys(info).forEach((key) => {
        let name = key;
        if (name.includes('_') || name.includes('-')) {
          name = camel(name);
        }
        tokenInfo[name] = info[key];
      });
    } else {
      tokenInfo = {};
      const params = new URLSearchParams(body);
      params.forEach((value, key) => {
        let name = key;
        if (key.includes('_') || key.includes('-')) {
          name = camel(key);
        }
        tokenInfo[name] = value;
      });
    }
    return tokenInfo;
  }

  /**
   * @param {Record<string, any>} info
   * @return {TokenInfo} The token info when the request was a success.
   */
  mapCodeResponse(info) {
    if (info.error) {
      throw new CodeError(info.errorDescription, info.error);
    }
    const expiresIn = Number(info.expiresIn);
    const scope = this[computeTokenInfoScopes](info.scope);
    const result = /** @type TokenInfo */ ({
      ...info,
      expiresIn,
      scope,
      expiresAt: undefined,
      expiresAssumed: false,
    });
    return this[computeExpires](result);
  }

  /**
   * Exchanges the authorization code for authorization token.
   *
   * @param {string} code Returned code from the authorization endpoint.
   * @return {Promise<TokenInfo>} The token info when the request was a success.
   */
  async exchangeCode(code) {
    const info = await this.getCodeInfo(code);
    return this.mapCodeResponse(info);
  }

  /**
   * Returns a body value for the code exchange request.
   * @param {string} code Authorization code value returned by the authorization server.
   * @return {string} Request body.
   */
  getCodeRequestBody(code) {
    const settings = this[settingsValue];
    const params = new URLSearchParams();
    params.set('grant_type', 'authorization_code');
    params.set('client_id', settings.clientId);
    if (settings.redirectUri) {
      params.set('redirect_uri', settings.redirectUri);
    }
    params.set('code', code);
    if (settings.clientSecret) {
      params.set('client_secret', settings.clientSecret);
    } else {
      params.set('client_secret', '');
    }
    if (settings.pkce) {
      params.set('code_verifier', this.#codeVerifier);
    }
    return params.toString();
  }

  /**
   * @param {string} url
   * @param {object} headers
   * @param {string} body
   * @return {Promise<FetchResponse>}
   */
  fetchToken(url, headers, body) {
    return new Promise((resolve, reject) => {
      const request = net.request({
        method: 'POST',
        session: this.#session,
        url,
      });
      Object.keys(headers).forEach((key) => {
        request.setHeader(key, headers[key]);
      });
      request.on('response', (response) => {
        const ro = /** @type FetchResponse */ ({
          status: response.statusCode,
          headers: response.headers,
          body: '',
        });
        response.on('data', (chunk) => {
          ro.body += chunk;
        });
        response.on('end', () => resolve(ro));
      });
      request.on('error', (error) => reject(error));
      request.write(body);
      request.end();
    });
  }

  /**
   * A handler for the error that happened during code exchange.
   * @param {Error} e
   */
  [handleTokenCodeError](e) {
    if (e instanceof CodeError) {
      // @ts-ignore
      this[reportOAuthError](...this[createErrorParams](e.message, e.code));
    } else {
      this[reportOAuthError](`Couldn't connect to the server. ${e.message}`, 'request_error');
    }
  }

  /**
   * Requests a token for `client_credentials` request type.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return {Promise<void>} Promise resolved to a token info object.
   */
  async [authorizeClientCredentials]() {
    const settings = this[settingsValue];
    const { accessTokenUri, deliveryMethod='body', deliveryName='authorization' } = settings;
    const body = this.getClientCredentialsBody();
    let headers = /** @type Record<string, string> */ (null);
    const headerTransport = deliveryMethod === 'header';
    if (headerTransport) {
      headers = {
        [deliveryName]: this.getClientCredentialsHeader(settings),
      };
    }
    try {
      const info = await this.requestTokenInfo(accessTokenUri, body, headers);
      const tokenInfo = this.mapCodeResponse(info);
      this[handleTokenInfo](tokenInfo);
    } catch (cause) {
      this[handleTokenCodeError](cause);
    }
  }

  /**
   * Generates a payload message for client credentials.
   *
   * @return {string} Message body as defined in OAuth2 spec.
   */
  getClientCredentialsBody() {
    const settings = this[settingsValue];
    const headerTransport = settings.deliveryMethod === 'header';
    const params = new URLSearchParams();
    params.set('grant_type', 'client_credentials');
    if (!headerTransport && settings.clientId) {
      params.set('client_id', settings.clientId);
    }
    if (!headerTransport && settings.clientSecret) {
      params.set('client_secret', settings.clientSecret);
    }
    if (Array.isArray(settings.scopes) && settings.scopes.length) {
      params.set('scope', settings.scopes.join(' '));
    }
    return params.toString();
  }

  /**
   * Builds the authorization header for Client Credentials grant type.
   * According to the spec the authorization header for this grant type
   * is the Base64 of `clientId` + `:` + `clientSecret`.
   *
   * @param {OAuth2Authorization} settings The OAuth 2 settings to use
   * @return {string}
   */
  getClientCredentialsHeader(settings) {
    const { clientId='', clientSecret='' } = settings;
    const buffer = Buffer.from(`${clientId}:${clientSecret}`);
    const hash = buffer.toString('base64');
    return `Basic ${hash}`;
  }

  /**
   * Requests a token for `client_credentials` request type.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return {Promise<void>} Promise resolved to a token info object.
   */
  async [authorizePassword]() {
    const settings = this[settingsValue];
    const url = settings.accessTokenUri;
    const body = this.getPasswordBody();
    try {
      const info = await this.requestTokenInfo(url, body);
      const tokenInfo = this.mapCodeResponse(info);
      this[handleTokenInfo](tokenInfo);
    } catch (cause) {
      this[handleTokenCodeError](cause);
    }
  }

  /**
   * Generates a payload message for password authorization.
   *
   * @return {string} Message body as defined in OAuth2 spec.
   */
  getPasswordBody() {
    const settings = this[settingsValue];
    const params = new URLSearchParams();
    params.set('grant_type', 'password');
    params.set('username', settings.username);
    params.set('password', settings.password);
    if (settings.clientId) {
      params.set('client_id', settings.clientId);
    }
    if (settings.clientSecret) {
      params.set('client_secret', settings.clientSecret);
    }
    if (Array.isArray(settings.scopes) && settings.scopes.length) {
      params.set('scope', settings.scopes.join(' '));
    }
    return params.toString();
  }

  /**
   * Performs authorization on custom grant type.
   * This extension is described in OAuth 2.0 spec.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return {Promise<void>} Promise resolved when the request finish.
   */
  async [authorizeCustomGrant]() {
    const settings = this[settingsValue];
    const url = settings.accessTokenUri;
    const body = this.getCustomGrantBody();
    try {
      const info = await this.requestTokenInfo(url, body);
      const tokenInfo = this.mapCodeResponse(info);
      this[handleTokenInfo](tokenInfo);
    } catch (cause) {
      this[handleTokenCodeError](cause);
    }
  }

  /**
   * Generates a payload message for the custom grant.
   *
   * @return {string} Message body as defined in OAuth2 spec.
   */
  getCustomGrantBody() {
    const settings = this[settingsValue];
    const params = new URLSearchParams();
    params.set('grant_type', settings.grantType);
    if (settings.clientId) {
      params.set('client_id', settings.clientId);
    }
    if (settings.clientSecret) {
      params.set('client_secret', settings.clientSecret);
    }
    if (Array.isArray(settings.scopes) && settings.scopes.length) {
      params.set('scope', settings.scopes.join(' '));
    }
    if (settings.redirectUri) {
      params.set('redirect_uri', settings.redirectUri);
    }
    if (settings.username) {
      params.set('username', settings.username);
    }
    if (settings.password) {
      params.set('password', settings.password);
    }
    return params.toString();
  }

  /**
   * Requests a token for the `urn:ietf:params:oauth:grant-type:device_code` response type.
   *
   * @return {Promise<void>} Promise resolved to a token info object.
   */
  async [authorizeDeviceCode]() {
    const settings = this[settingsValue];
    const url = settings.accessTokenUri;
    const body = this.getDeviceCodeBody();
    try {
      const info = await this.requestTokenInfo(url, body);
      const tokenInfo = this.mapCodeResponse(info);
      this[handleTokenInfo](tokenInfo);
    } catch (cause) {
      this[handleTokenCodeError](cause);
    }
  }

  /**
   * Generates a payload message for the `urn:ietf:params:oauth:grant-type:device_code` authorization.
   *
   * @return {string} Message body as defined in OAuth2 spec.
   */
  getDeviceCodeBody() {
    const settings = this[settingsValue];
    const params = new URLSearchParams();
    params.set('grant_type', KnownGrants.deviceCode);
    params.set('device_code', settings.deviceCode);
    if (settings.clientId) {
      params.set('client_id', settings.clientId);
    }
    if (settings.clientSecret) {
      params.set('client_secret', settings.clientSecret);
    }
    return params.toString();
  }

  /**
   * Requests a token for the `urn:ietf:params:oauth:grant-type:jwt-bearer` response type.
   *
   * @return {Promise<void>} Promise resolved to a token info object.
   */
  async [authorizeJwt]() {
    const settings = this[settingsValue];
    const url = settings.accessTokenUri;
    const body = this.getJwtBody();
    try {
      const info = await this.requestTokenInfo(url, body);
      const tokenInfo = this.mapCodeResponse(info);
      this[handleTokenInfo](tokenInfo);
    } catch (cause) {
      this[handleTokenCodeError](cause);
    }
  }

  /**
   * Generates a payload message for the `urn:ietf:params:oauth:grant-type:jwt-bearer` authorization.
   *
   * @return {string} Message body as defined in OAuth2 spec.
   */
  getJwtBody() {
    const settings = this[settingsValue];
    const params = new URLSearchParams();
    params.set('grant_type', KnownGrants.jwtBearer);
    params.set('assertion', settings.assertion);
    if (Array.isArray(settings.scopes) && settings.scopes.length) {
      params.set('scope', settings.scopes.join(' '));
    }
    return params.toString();
  }

  /**
   * Processes the response returned by the popup or the iframe.
   * @param {URLSearchParams} oauthParams
   * @return {string[]} Parameters for the [reportOAuthError]() function
   */
  createTokenResponseError(oauthParams) {
    const code = oauthParams.get('error');
    const message = oauthParams.get('error_description');
    return this[createErrorParams](code, message);
  }

  /**
   * Creates arguments for the error function from error response
   * @param {string} code Returned from the authorization server error code
   * @param {string=} description Returned from the authorization server error description
   * @return {string[]} Parameters for the [reportOAuthError]() function
   */
  [createErrorParams](code, description) {
    let message;
    if (description) {
      message = description;
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
        default:
          message = i18n.__('Unknown error');
      }
    }
    return [message, code];
  }

  /**
   * A handler for `onComplete` of session's webRequest object.
   * @param {Electron.OnCompletedListenerDetails} detail
   */
  [sessionCompletedListener](detail) {
    if (detail.resourceType !== 'mainFrame' || !this.#oauthWindowListening) {
      return;
    }
    const { statusCode, url } = detail;
    const rUri = this[settingsValue].redirectUri;
    if (statusCode >= 400) {
      // This is an error. Redirect URL can be a fake and this should catch valid response in 400 status code.
      if (url.indexOf(rUri) !== 0) {
        this[reportOAuthError](i18n.__('ERR_CONFIG_ERROR'), 'uri_error');
      }
    } else if (url.indexOf(rUri) === 0) {
      if (this.#loadPopupTimeout) {
        clearTimeout(this.#loadPopupTimeout);
      }
      this.unobserveAuthWindow();
      this[processPopupRawData](url);
    } else if (this[settingsValue].interactive === false) {
      this.#loadPopupTimeout = setTimeout(() => {
        this[reportOAuthError](i18n.__('ERR_SERVER_ERROR'), 'auth_error');
      }, 1000);
    }
  }

  /**
   * A handler for the `onErrorOccurred` event of the session's webRequest object.
   * @param {Electron.OnErrorOccurredListenerDetails} detail
   */
  [sessionErrorListener](detail) {
    const { error, url } = detail;
    const rUri = this[settingsValue].redirectUri;
    if (url.indexOf(rUri) === 0) {
      this.unobserveAuthWindow();
      if (this.#loadPopupTimeout) {
        clearTimeout(this.#loadPopupTimeout);
      }
      this[processPopupRawData](url);
      return;
    }
    const aUri = this[settingsValue].authorizationUri;
    if (aUri.startsWith(url)) {
      this.unobserveAuthWindow();
      if (this.#loadPopupTimeout) {
        clearTimeout(this.#loadPopupTimeout);
      }
      this[reportOAuthError](error, 'auth_error');
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
    const info = await this.restoreTokenInfo();
    if (!info || !info.accessToken) {
      return;
    }
    if (this.isExpired(info)) {
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
}
