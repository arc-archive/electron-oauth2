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
const {ipcMain, app} = require('electron');
const fs = require('fs-extra');
const path = require('path');
const {IdentityProvider} = require('./provider');
/**
 * Class that manages OAuth2 identities.
 */
class Oauth2Identity {
  /**
   * Listens for the renderer process events related to OAuth provider.
   */
  static listen() {
    ipcMain.on('oauth-2-get-token', Oauth2Identity._getTokenHandler);
    ipcMain.on('oauth-2-launch-web-flow', Oauth2Identity._launchWebFlowHandler);
  }
  /**
   * Handler for the `oauth-2-get-token` event from the render process.
   * Lunches the default OAuth flow with properties read from the manifest file.
   *
   * @param {Object} e
   * @param {Object} options Oauth options. See `Oauth2Identity.getAuthToken`
   * for description
   */
  static _getTokenHandler(e, options) {
    Oauth2Identity.getAuthToken(options)
    .then((token) => {
      e.sender.send('oauth-2-token-ready', token);
    })
    .catch((cause) => {
      e.sender.send('oauth-2-token-error', cause);
    });
  }
  /**
   * Handler for the `oauth-2-launch-web-flow` event from the render process.
   * Lunches OAuth flow in browser window.
   *
   * @param {Object} e
   * @param {Object} options Oauth options. See `Oauth2Identity.launchWebAuthFlow`
   * for description
   * @param {String} id Id generated in the renderer to recognize the request.
   */
  static _launchWebFlowHandler(e, options, id) {
    Oauth2Identity.launchWebAuthFlow(options)
    .then((token) => {
      e.sender.send('oauth-2-token-ready', token, id);
    })
    .catch((cause) => {
      e.sender.send('oauth-2-token-error', cause, id);
    });
  }
  /**
   * Generates a provider ID as an identifier for an identity
   *
   * @param {String} authUri User authorization URI
   * @param {String} clientId Client ID
   * @return {String} An ID to be used to identity a provider.
   */
  static _generateProviderId(authUri, clientId) {
    return encodeURIComponent(authUri) + '/' + encodeURIComponent(clientId);
  }
  /**
   * Adds a provider to the list of existing (cached) providers.
   *
   * @param {IdentityProvider} provider Provider to cache.
   */
  static _addProvider(provider) {
    if (!Oauth2Identity.__providers) {
      Oauth2Identity.__providers = [];
    }
    Oauth2Identity.__providers.push(provider);
  }
  /**
   * Looks for existing OAuth provider with (possibly) cached auth data.
   *
   * @param {String} authUri Authorization URL
   * @param {String} clientId Client ID used to authenticate.
   * @return {IdentityProvider} An identity provider or `undefined` if
   * not exists.
   */
  static _getProvider(authUri, clientId) {
    if (!Oauth2Identity.__providers) {
      return;
    }
    const id = Oauth2Identity._generateProviderId(authUri, clientId);
    return Oauth2Identity.__providers.find((item) => item.id === id);
  }
  /**
   * Runs the web authorization flow.
   * @param {Object} opts Authorization options
   * - `interactive` {Boolean} If the interactive flag is `true`,
   * `launchWebAuthFlow` will prompt the user as necessary. When the flag
   * is `false` or omitted,
   * `launchWebAuthFlow` will return failure any time a prompt would be
   * required.
   * - `response_type` or `type` {String} `code` or `token`.
   * - `scopes` {Array<String>} List of scopes to authorize
   * - `client_id` or `clientId` {String} The client ID used for authorization
   * - `auth_uri` or `authorizationUri` {String} Authorization URI
   * - `token_uri` or `accessTokenUri` {String} Optional, required if `response_type` is code
   * - `redirect_uri` or `redirectUri` {String} Auth redirect URI
   * - `client_secret` or `clientSecret` {String} Optional, required if `response_type` is code
   * - `include_granted_scopes` {Boolean} Optional.
   * - `login_hint` {String} Optional, user email
   * - `state`
   * @return {Promise} A promise with auth result.
   */
  static launchWebAuthFlow(opts) {
    const provider = Oauth2Identity._getOrCreateProvider(opts);
    if (provider.tokenInfo) {
      if (!provider.isExpired(provider.tokenInfo)) {
        if (opts.state) {
          provider.tokenInfo.state = opts.state;
        } else {
          delete provider.tokenInfo.state;
        }
        return Promise.resolve(provider.tokenInfo);
      }
    }
    return provider.launchWebAuthFlow(opts);
  }
  /**
   * A method to call to authorize the user in Google authorization services.
   *
   * @param {Object} opts Authorization options
   * - `interactive` {Boolean} If the interactive flag is `true`, `getAuthToken`
   * will prompt the user as necessary. When the flag is `false` or omitted,
   * `getAuthToken` will return failure any time a prompt would be required.
   * - `scopes` {Array<String>} List of scopes to authorize
   * @return {Promise} A promise resulted to the auth token.
   */
  static getAuthToken(opts) {
    return Oauth2Identity.getOAuthConfig()
    .then((config) => {
      if (!config) {
        throw new Error('"oauth2" key missing in package.json');
      }
      return Oauth2Identity._getOrCreateProvider(config);
    })
    .then((provider) => provider.getAuthToken(opts));
  }
  /**
   * Reads the default OAuth configuration for the app from package file.
   *
   * @return {Promise} A promise resolved to OAuth2 configuration object
   */
  static getOAuthConfig() {
    const file = path.join(app.getAppPath(), 'package.json');
    return fs.readJson(file)
    .then((packageInfo) => packageInfo.oauth2);
  }
  /**
   * Returns chached provider or creates new provider based on the oauth
   * configuration.
   *
   * @param {Object} oauthConfig OAuth2 configuration object.
   * @return {IdentityProvider} Identity provider for given config.
   */
  static _getOrCreateProvider(oauthConfig) {
    const authUri = oauthConfig.auth_uri || oauthConfig.authorizationUri;
    const clientId = oauthConfig.client_id || oauthConfig.clientId;
    let provider = Oauth2Identity._getProvider(authUri, clientId);
    if (!provider) {
      const id = Oauth2Identity._generateProviderId(authUri, clientId);
      const cnf = Object.assign({}, oauthConfig);
      if (!cnf.response_type && !cnf.type) {
        cnf.response_type = 'implicit';
        cnf.include_granted_scopes = true;
      }
      provider = new IdentityProvider(id, cnf);
      Oauth2Identity._addProvider(provider);
    }
    return provider;
  }
}
exports.Oauth2Identity = Oauth2Identity;
