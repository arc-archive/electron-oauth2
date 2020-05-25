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
import { ipcMain, app } from 'electron';
import fs from 'fs-extra';
import path from 'path';
import { IdentityProvider } from './provider.js';
import i18n from 'i18n';

i18n.configure({
  directory: path.join(__dirname, '..', '/locales'),
  updateFiles: false,
});

/** @typedef {import('./provider').TokenInfo} TokenInfo */
/** @typedef {import('./provider').AuthorizationOptions} AuthorizationOptions */
/** @typedef {import('./provider').BaseOptions} BaseOptions */
/** @typedef {import('./provider').TokenRemoveOptions} TokenRemoveOptions */

const providers = [];
/**
 * Class that manages OAuth2 identities.
 */
export class Oauth2Identity {
  /**
   * Listens for the renderer process events related to OAuth provider.
   */
  static listen() {
    ipcMain.on('oauth-2-get-token', Oauth2Identity._getTokenHandler);
    ipcMain.on('oauth-2-launch-web-flow', Oauth2Identity._launchWebFlowHandler);
    ipcMain.on('oauth-2-remove-token', Oauth2Identity._removeTokenHandler);

    ipcMain.handle('oauth2-gettoken', Oauth2Identity._handleTokenRequest);
    ipcMain.handle('oauth2-launchwebflow', Oauth2Identity._handleLaunchWebFlow);
    ipcMain.handle('oauth2-removetoken', Oauth2Identity._handleRemoveToken);
  }

  /**
   * Handler for the `oauth-2-get-token` event from the render process.
   * Lunches the default OAuth flow with properties read from the manifest file.
   *
   * @param {Electron.IpcMainEvent} e
   * @param {AuthorizationOptions} options Oauth options.
   */
  static async _getTokenHandler(e, options) {
    try {
      const token = await Oauth2Identity.getAuthToken(options);
      e.sender.send('oauth-2-token-ready', token);
    } catch (cause) {
      e.sender.send('oauth-2-token-error', cause);
    }
  }

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param {Electron.IpcMainEvent} e
   * @param {AuthorizationOptions} options Oauth options.
   * @return {Promise<TokenInfo>} Promise resolved to the token object.
   */
  static async _handleTokenRequest(e, options) {
    return Oauth2Identity.getAuthToken(options);
  }

  /**
   * Handler for the `oauth-2-launch-web-flow` event from the render process.
   * Lunches OAuth flow in browser window.
   *
   * @param {Electron.IpcMainEvent} e
   * @param {AuthorizationOptions} options Oauth options.
   * @param {String} id Id generated in the renderer to recognize the request.
   */
  static async _launchWebFlowHandler(e, options, id) {
    try {
      const token = await Oauth2Identity.launchWebAuthFlow(options);
      e.sender.send('oauth-2-token-ready', token, id);
    } catch (cause) {
      e.sender.send('oauth-2-token-error', cause, id);
    }
  }

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param {Electron.IpcMainEvent} e
   * @param {AuthorizationOptions} options Oauth options.
   * @return {Promise<TokenInfo>} Promise resolved to the token object.
   */
  static async _handleLaunchWebFlow(e, options) {
    return Oauth2Identity.launchWebAuthFlow(options);
  }

  /**
   * Handler for the `oauth-2-remove-token` event from the render process.
   * Removes chaced token data and token info from provider.
   *
   * @param {Electron.IpcMainEvent} e
   * @param {TokenRemoveOptions} options Oauth options.
   * @param {string} id Id generated in the renderer to recognize the request.
   */
  static async _removeTokenHandler(e, options, id) {
    try {
      await Oauth2Identity.removeToken(options);
      e.sender.send('oauth-2-token-removed', id);
    } catch (cause) {
      e.sender.send('oauth-2-token-error', cause, id);
    }
  }

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param {Electron.IpcMainEvent} e
   * @param {TokenRemoveOptions} options Oauth options.
   */
  static async _handleRemoveToken(e, options) {
    await Oauth2Identity.removeToken(options);
  }

  /**
   * Generates a provider ID as an identifier for an identity
   *
   * @param {string} authUri User authorization URI
   * @param {string} clientId Client ID
   * @return {String} An ID to be used to identity a provider.
   */
  static _generateProviderId(authUri, clientId) {
    const aUri = encodeURIComponent(authUri);
    const cUri = encodeURIComponent(clientId);
    return `${aUri}/${cUri}`;
  }

  /**
   * Adds a provider to the list of existing (cached) providers.
   *
   * @param {IdentityProvider} provider Provider to cache.
   */
  static _addProvider(provider) {
    providers.push(provider);
  }

  /**
   * Looks for existing OAuth provider with (possibly) cached auth data.
   *
   * @param {string} authUri Authorization URL
   * @param {string} clientId Client ID used to authenticate.
   * @return {IdentityProvider} An identity provider or `undefined` if
   * not exists.
   */
  static _getProvider(authUri, clientId) {
    if (!providers.length) {
      return;
    }
    const id = Oauth2Identity._generateProviderId(authUri, clientId);
    return providers.find((item) => item.id === id);
  }

  /**
   * Runs the web authorization flow.
   * @param {AuthorizationOptions} opts Authorization options
   * @return {Promise<TokenInfo>} A promise with auth result.
   */
  static async launchWebAuthFlow(opts) {
    const provider = Oauth2Identity._getOrCreateProvider(opts);
    if (provider.tokenInfo) {
      if (!provider.isExpired(provider.tokenInfo)) {
        if (opts.state) {
          provider.tokenInfo.state = opts.state;
        } else {
          delete provider.tokenInfo.state;
        }
        return provider.tokenInfo;
      }
    }
    return provider.launchWebAuthFlow(opts);
  }

  /**
   * A method to call to authorize the user in Google authorization services.
   *
   * @param {BaseOptions} opts Authorization options
   * @return {Promise<TokenInfo>} A promise resulted to the auth token.
   */
  static async getAuthToken(opts) {
    const config = await Oauth2Identity.getOAuthConfig();
    if (!config) {
      throw new Error('"oauth2" key missing in package.json');
    }
    const provider = await Oauth2Identity._getOrCreateProvider(config);
    return provider.getAuthToken(opts);
  }

  /**
   * Removes cached token info.
   *
   * @param {TokenRemoveOptions=} opts When provided it is the same as for
   * `launchWebAuthFlow()` function. When not set it reads `package.json`
   * object for oauth2 configuration.
   * @return {Promise<void>}
   */
  static async removeToken(opts) {
    if (!opts) {
      opts = /** @type TokenRemoveOptions */ (await Oauth2Identity.getOAuthConfig());
    }
    const provider = await Oauth2Identity._getOrCreateProvider(opts);
    await provider.clearCache();
  }

  /**
   * Reads the default OAuth configuration for the app from package file.
   *
   * @return {Promise<AuthorizationOptions>} A promise resolved to OAuth2 configuration object
   */
  static async getOAuthConfig() {
    const file = path.join(app.getAppPath(), 'package.json');
    try {
      const packageInfo = await fs.readJson(file);
      return packageInfo.oauth2;
    } catch (e) {
      return undefined;
    }
  }

  /**
   * Returns chached provider or creates new provider based on the oauth
   * configuration.
   *
   * @param {AuthorizationOptions} oauthConfig OAuth2 configuration object.
   * @return {IdentityProvider} Identity provider for given config.
   */
  static _getOrCreateProvider(oauthConfig) {
    const authUri = oauthConfig.auth_uri || oauthConfig.authorizationUri;
    const clientId = oauthConfig.client_id || oauthConfig.clientId;
    let provider = Oauth2Identity._getProvider(authUri, clientId);
    if (!provider) {
      const id = Oauth2Identity._generateProviderId(authUri, clientId);
      const cnf = { ...oauthConfig };
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
