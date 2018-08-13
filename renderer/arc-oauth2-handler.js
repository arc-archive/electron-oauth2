const {ipcRenderer} = require('electron');
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
    this._requestId = 0;
    this._activeIds = {};
  }
  /**
   * Attaches listeners on the body element to listen for elements events.
   */
  listen() {
    document.body.addEventListener('oauth2-token-requested',
      this._tokenRequestedHandler);
    ipcRenderer.on('oauth-2-token-ready', this._tokenReadyHandler);
    ipcRenderer.on('oauth-2-token-error', this._tokenErrorHandler);
  }
  /**
   * Removes any event listeners registered by this class.
   */
  unlisten() {
    document.body.removeEventListener('oauth2-token-requested',
      this._tokenRequestedHandler);
    ipcRenderer.removeListener('oauth-2-token-ready', this._tokenReadyHandler);
    ipcRenderer.removeListener('oauth-2-token-error', this._tokenErrorHandler);
  }
  /**
   * Handler for the `oauth2-token-requested` custom event.
   *
   * @param {Event} e Request custom event.
   */
  _tokenRequestedHandler(e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    let interactive;
    if (typeof e.detail.interactive === 'boolean') {
      interactive = e.detail.interactive;
    }
    let state;
    if (!e.detail.state) {
      state = this.generateState();
    } else {
      state = e.detail.state;
    }
    const opts = {
      interactive,
      type: e.detail.type,
      clientId: e.detail.clientId,
      clientSecret: e.detail.clientSecret,
      authorizationUri: e.detail.authorizationUri,
      accessTokenUri: e.detail.accessTokenUrl,
      redirectUri: e.detail.redirectUri,
      username: e.detail.username,
      password: e.detail.password,
      scopes: e.detail.scopes,
      state: state,
      customData: e.detail.customData
    };
    const id = (++this._requestId);
    this._activeIds[id] = opts;
    ipcRenderer.send('oauth-2-launch-web-flow', opts, id);
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
   * @param {Strnig} type Event name
   * @param {Object} detail Value of the detail object.
   */
  fire(type, detail) {
    const ev = new CustomEvent(type, {
      bubbles: true,
      detail: detail
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
   * @param {Event} e
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
      code: cause.code || 'unknown_error'
    };
    if (cause.state) {
      detail.state = cause.state;
    }
    this.fire('oauth2-error', detail);
  }
  /**
   * Handler for succesful OAuth token request.
   *
   * @param {Event} e
   * @param {Object} tokenInfo Token info object
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
}

exports.OAuth2Handler = OAuth2Handler;
