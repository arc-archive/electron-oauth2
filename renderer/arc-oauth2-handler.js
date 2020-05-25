const { ipcRenderer } = require('electron');

/** @typedef {import('./../lib/provider').AuthorizationOptions} AuthorizationOptions */
/** @typedef {import('./../lib/provider').TokenInfo} TokenInfo */
/** @typedef {import('./../lib/provider').TokenRemoveOptions} TokenRemoveOptions */

/**
 * Class responsible for handing OAuth2 related events and to pass them to
 * the main script for futher processing.
 */
class OAuth2Handler {
  /**
   * @constructor
   */
  constructor() {
    this._tokenRequestedHandler = this._tokenRequestedHandler.bind(this);
    this._tokenErrorHandler = this._tokenErrorHandler.bind(this);
    this._tokenReadyHandler = this._tokenReadyHandler.bind(this);
    this._tokenRemovedHandler = this._tokenRemovedHandler.bind(this);
    this._tokenRemoveHandler = this._tokenRemoveHandler.bind(this);
    this._launchFlowHandler = this._launchFlowHandler.bind(this);
    this._tokenPromiseRemoveHandler = this._tokenPromiseRemoveHandler.bind(this);
    this._requestId = 0;
    this._activeIds = {};
  }

  /**
   * Attaches listeners on the body element to listen for elements events.
   */
  listen() {
    document.body.addEventListener(
      'oauth2-token-requested',
      this._tokenRequestedHandler,
    );
    document.body.addEventListener(
      'oauth2-token-remove',
      this._tokenRemoveHandler,
    );
    document.body.addEventListener(
      'oauth2-launchwebflow',
      this._launchFlowHandler,
    );
    document.body.addEventListener(
      'oauth2-removetoken',
      this._tokenPromiseRemoveHandler,
    );
    ipcRenderer.on('oauth-2-token-ready', this._tokenReadyHandler);
    ipcRenderer.on('oauth-2-token-error', this._tokenErrorHandler);
    ipcRenderer.on('oauth-2-token-removed', this._tokenRemovedHandler);
  }

  /**
   * Removes any event listeners registered by this class.
   */
  unlisten() {
    document.body.removeEventListener(
      'oauth2-token-requested',
      this._tokenRequestedHandler,
    );
    document.body.removeEventListener(
      'oauth2-token-remove',
      this._tokenRemoveHandler,
    );
    document.body.removeEventListener(
      'oauth2-launchwebflow',
      this._launchFlowHandler,
    );
    document.body.removeEventListener(
      'oauth2-removetoken',
      this._tokenPromiseRemoveHandler,
    );
    ipcRenderer.removeListener('oauth-2-token-ready', this._tokenReadyHandler);
    ipcRenderer.removeListener('oauth-2-token-error', this._tokenErrorHandler);
    ipcRenderer.removeListener(
      'oauth-2-token-removed',
      this._tokenRemovedHandler,
    );
  }

  /**
   * Requests for a token from the main process.
   * @param {AuthorizationOptions} opts Auth options.
   * @return {Promise<TokenInfo>} The token info object.
   */
  async requestToken(opts) {
    return ipcRenderer.invoke('oauth2-launchwebflow', opts);
  }

  /**
   * Handler for the `oauth2-launchwebflow` custom event.
   * This sets a promise on the `detail.result` object instead of
   * dispatching event with the token.
   *
   * @param {CustomEvent} e
   */
  _launchFlowHandler(e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    const opts = this._prepareEventDetail(e.detail);
    e.detail.result = this.requestToken(opts);
  }

  /**
   * Handler for the `oauth2-token-requested` custom event.
   *
   * @param {CustomEvent} e Request custom event.
   */
  _tokenRequestedHandler(e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    const opts = this._prepareEventDetail(e.detail);
    const id = ++this._requestId;
    this._activeIds[id] = opts;
    ipcRenderer.send('oauth-2-launch-web-flow', opts, id);
  }

  /**
   * Prepares OAuth 2 config from the event detail.
   * @param {object} detail Event's detail object
   * @return {AuthorizationOptions}
   */
  _prepareEventDetail(detail) {
    let interactive;
    if (typeof detail.interactive === 'boolean') {
      interactive = detail.interactive;
    }
    let state;
    if (!detail.state) {
      state = this.generateState();
    } else {
      state = detail.state;
    }
    const opts = {
      interactive,
      type: detail.type,
      clientId: detail.clientId,
      clientSecret: detail.clientSecret,
      authorizationUri: detail.authorizationUri,
      accessTokenUri: detail.accessTokenUri,
      redirectUri: detail.redirectUri,
      username: detail.username,
      password: detail.password,
      scopes: detail.scopes,
      state,
      customData: detail.customData,
      includeGrantedScopes: detail.includeGrantedScopes,
      loginHint: detail.loginHint,
    };
    return opts;
  }

  /**
   * Handler for the `oauth2-token-remove` custom event dispatched to
   * clear cached token info.
   *
   * The event's `detail` object is optional. When it is set and contains both
   * `clientId` and `authorizationUri` this data will be used to create
   * identity provider.
   * Otherwise it will use `package.json` file to get oauth configuration.
   * @param {CustomEvent} e
   */
  _tokenRemoveHandler(e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    const id = ++this._requestId;
    let opts;
    if (e.detail && e.detail.clientId && e.detail.authorizationUri) {
      // This is required to construct the provider ID.
      // When not set it reads package.json file for oauth config.
      opts = {
        clientId: e.detail.clientId,
        authorizationUri: e.detail.authorizationUri,
      };
    }
    ipcRenderer.send('oauth-2-remove-token', opts, id);
    if (!opts) {
      opts = {};
    }
    this._activeIds[id] = opts;
  }

  /**
   * Handler for the `oauth2-removetoken` custom event dispatched to
   * clear cached token info.
   *
   * It adds `result` on the detail object with the promise with the result of
   * removing the token.,
   * Configuration options are optional. When set and contains both
   * `clientId` and `authorizationUri` this data will be used to create
   * identity provider. Otherwise it uses `package.json` file to get oauth configuration.
   * @param {CustomEvent} e
   */
  _tokenPromiseRemoveHandler(e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    let opts;
    if (e.detail && e.detail.clientId && e.detail.authorizationUri) {
      opts = {
        clientId: e.detail.clientId,
        authorizationUri: e.detail.authorizationUri,
      };
    }
    e.detail.result = this.deleteToken(opts);
  }

  /**
   * Removes token from the chache.
   *
   * @param {TokenRemoveOptions=} opts
   * @return {Promise<void>}
   */
  async deleteToken(opts) {
    return ipcRenderer.invoke('oauth2-removetoken', opts);
  }

  /**
   * Generates `state` parameter for the OAuth2 call.
   *
   * @return {String} Generated state string.
   */
  generateState() {
    let text = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (let i = 0; i < 6; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return text;
  }

  /**
   * Fires custom event.
   *
   * @param {String} type Event name
   * @param {Object=} detail Value of the detail object.
   */
  fire(type, detail) {
    const ev = new CustomEvent(type, {
      bubbles: true,
      detail,
    });
    document.body.dispatchEvent(ev);
  }

  /**
   * Checks if given ID is on the active IDs lis, removes the ID from the list
   * and returns initial options for the request.
   *
   * @param {Number} id ID given back from the main process.
   * @return {Object|undefined} Request settings or undefined if not found
   */
  _checkAndRemoveRequestId(id) {
    const data = this._activeIds[id];
    if (data) {
      delete this._activeIds[id];
    }
    return data;
  }

  /**
   * Handler for the token error response.
   *
   * @param {Electron.IpcRendererEvent} e
   * @param {Object} cause Error info.
   * @param {Number} id Generated and sent to main process ID
   */
  _tokenErrorHandler(e, cause, id) {
    const settings = this._checkAndRemoveRequestId(id);
    if (!settings) {
      return;
    }
    const detail = {
      interactive: settings.interactive,
      message: cause.message || cause || 'Unknown error',
      code: cause.code || 'unknown_error',
    };
    if (cause.state) {
      detail.state = cause.state;
    }
    this.fire('oauth2-error', detail);
  }

  /**
   * Handler for succesful OAuth token request.
   *
   * @param {Electron.IpcRendererEvent} e
   * @param {TokenInfo} tokenInfo Token info object
   * @param {Number} id Generated and sent to main process ID
   */
  _tokenReadyHandler(e, tokenInfo, id) {
    const settings = this._checkAndRemoveRequestId(id);
    if (!settings) {
      return;
    }
    if (!tokenInfo.state && settings.state) {
      tokenInfo.state = settings.state;
    }
    tokenInfo.interactive = settings.interactive;
    this.fire('oauth2-token-response', tokenInfo);
  }

  /**
   * Handler for oauth-2-token-removed main event.
   *
   * @param {Electron.IpcRendererEvent} e
   * @param {number} id Generated and sent to main process ID
   */
  _tokenRemovedHandler(e, id) {
    const settings = this._checkAndRemoveRequestId(id);
    if (!settings) {
      return;
    }
    this.fire('oauth2-token-removed');
  }
}

exports.OAuth2Handler = OAuth2Handler;
