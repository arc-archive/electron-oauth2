import { ipcRenderer } from 'electron';
import { AuthorizationEventTypes } from '@advanced-rest-client/arc-events';

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenInfo} TokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenRemoveOptions} TokenRemoveOptions */
/** @typedef {import('@advanced-rest-client/arc-events').OAuth2AuthorizeEvent} OAuth2AuthorizeEvent */
/** @typedef {import('@advanced-rest-client/arc-events').OAuth2RemoveTokenEvent} OAuth2RemoveTokenEvent */

export const authorizeHandler = Symbol('authorizeHandler');
export const removeTokenHandler = Symbol('removeTokenHandler');
export const prepareEventDetail = Symbol('prepareEventDetail');

/**
 * Class responsible for handing OAuth2 related events and to pass them to
 * the main script for further processing.
 */
export class OAuth2Handler {
  /**
   * @constructor
   */
  constructor() {
    this[authorizeHandler] = this[authorizeHandler].bind(this);
    this[removeTokenHandler] = this[removeTokenHandler].bind(this);
  }

  /**
   * Attaches listeners on the body element to listen for elements events.
   */
  listen() {
    const types = AuthorizationEventTypes.OAuth2;
    document.body.addEventListener(types.authorize, this[authorizeHandler]);
    document.body.addEventListener(types.removeToken, this[removeTokenHandler]);
  }

  /**
   * Removes any event listeners registered by this class.
   */
  unlisten() {
    const types = AuthorizationEventTypes.OAuth2;
    document.body.removeEventListener(types.authorize, this[authorizeHandler]);
    document.body.removeEventListener(types.removeToken, this[removeTokenHandler]);
  }

  /**
   * Requests for a token from the main process.
   * @param {OAuth2Authorization} opts Auth options.
   * @return {Promise<TokenInfo>} The token info object.
   */
  async requestToken(opts) {
    return ipcRenderer.invoke('oauth2-launchwebflow', opts);
  }

  /**
   * Prepares OAuth 2 config from the event detail.
   * @param {OAuth2Authorization} detail Event's detail object
   * @return {OAuth2Authorization}
   */
  [prepareEventDetail](detail) {
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
    const opts = /** @type OAuth2Authorization */ ({
      interactive,
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
    });
    return opts;
  }

  /**
   * Removes token from the cache.
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
   * Handler for the `oauth2-launchwebflow` custom event.
   * This sets a promise on the `detail.result` object instead of
   * dispatching event with the token.
   *
   * @param {OAuth2AuthorizeEvent} e
   */
  [authorizeHandler](e) {
    if (e.defaultPrevented) {
      return;
    }
    e.preventDefault();
    e.stopPropagation();
    const opts = this[prepareEventDetail](e.detail);
    e.detail.result = this.requestToken(opts);
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
   * @param {OAuth2RemoveTokenEvent} e
   */
  [removeTokenHandler](e) {
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
}
