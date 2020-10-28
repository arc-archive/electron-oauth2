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

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.BaseOAuth2Authorization} BaseOAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').OAuth2.TokenRemoveOptions} TokenRemoveOptions */
/** @typedef {import('@advanced-rest-client/arc-types').OAuth2.TokenInfo} TokenInfo */

const providers = [];

export const tokenRequestHandler = Symbol('tokenRequestHandler');
export const launchWebFlowHandler = Symbol('launchWebFlowHandler');
export const removeTokenHandler = Symbol('removeTokenHandler');

/**
 * Class that manages OAuth2 identities.
 */
export class Oauth2Identity {
  /**
   * The user agent to be set on the browser window when requesting for a token
   * in a browser flow. This allows to fix the issue with Google auth servers that
   * stopped supporting default electron user agent.
   */
  static userAgent = 'Chrome';

  /**
   * Listens for the renderer process events related to OAuth provider.
   */
  static listen() {
    ipcMain.handle('oauth2-gettoken', Oauth2Identity[tokenRequestHandler]);
    ipcMain.handle('oauth2-launchwebflow', Oauth2Identity[launchWebFlowHandler]);
    ipcMain.handle('oauth2-removetoken', Oauth2Identity[removeTokenHandler]);
  }

  /**
   * Removes listeners from the channels
   */
  static unlisten() {
    ipcMain.removeHandler('oauth2-gettoken');
    ipcMain.removeHandler('oauth2-launchwebflow');
    ipcMain.removeHandler('oauth2-removetoken');
  }

  /**
   * Asynchronous communication with the rendered process using Promises API.
   * @param {Electron.IpcMainEvent} e
   * @param {OAuth2Authorization} options Oauth options.
   * @return {Promise<TokenInfo>} Promise resolved to the token object.
   */
  static async [tokenRequestHandler](e, options) {
    return Oauth2Identity.getAuthToken(options);
  }

  /**
   * Lunches OAuth flow in browser window.
   * @param {Electron.IpcMainEvent} e
   * @param {OAuth2Authorization} options Oauth options.
   * @return {Promise<TokenInfo>} Promise resolved to the token object.
   */
  static async [launchWebFlowHandler](e, options) {
    return Oauth2Identity.launchWebAuthFlow(options);
  }

  /**
   * Removes cached token data and token info from provider.
   *
   * @param {Electron.IpcMainEvent} e
   * @param {TokenRemoveOptions} options Oauth options.
   */
  static async [removeTokenHandler](e, options) {
    await Oauth2Identity.removeToken(options);
  }

  /**
   * Generates a provider ID as an identifier for an identity
   *
   * @param {string} authUri User authorization URI
   * @param {string} clientId Client ID
   * @return {String} An ID to be used to identity a provider.
   */
  static generateProviderId(authUri, clientId) {
    const aUri = encodeURIComponent(authUri);
    const cUri = encodeURIComponent(clientId);
    return `${aUri}/${cUri}`;
  }

  /**
   * Adds a provider to the list of existing (cached) providers.
   *
   * @param {IdentityProvider} provider Provider to cache.
   */
  static addProvider(provider) {
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
  static getProvider(authUri, clientId) {
    if (!providers.length) {
      return;
    }
    const id = Oauth2Identity.generateProviderId(authUri, clientId);
    return providers.find((item) => item.id === id);
  }

  /**
   * Runs the web authorization flow.
   * @param {OAuth2Authorization} opts Authorization options
   * @return {Promise<TokenInfo>} A promise with auth result.
   */
  static async launchWebAuthFlow(opts) {
    const provider = Oauth2Identity.getOrCreateProvider(opts);
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
   * @param {BaseOAuth2Authorization} opts Authorization options
   * @return {Promise<TokenInfo>} A promise resulted to the auth token.
   */
  static async getAuthToken(opts) {
    const config = await Oauth2Identity.getOAuthConfig();
    if (!config) {
      throw new Error('"oauth2" key missing in package.json');
    }
    const provider = Oauth2Identity.getOrCreateProvider(config);
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
    const provider = Oauth2Identity.getOrCreateProvider(opts);
    provider.clearCache();
  }

  /**
   * Reads the default OAuth configuration for the app from package file.
   *
   * @return {Promise<OAuth2Authorization>} A promise resolved to OAuth2 configuration object
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
   * Returns cached provider or creates new provider based on the oauth
   * configuration.
   *
   * @param {OAuth2Authorization} oauthConfig OAuth2 configuration object.
   * @return {IdentityProvider} Identity provider for given config.
   */
  static getOrCreateProvider(oauthConfig) {
    const authUri = oauthConfig.authorizationUri;
    const clientId = oauthConfig.clientId;
    let provider = Oauth2Identity.getProvider(authUri, clientId);
    if (!provider) {
      const id = Oauth2Identity.generateProviderId(authUri, clientId);
      const cnf = { ...oauthConfig };
      if (!cnf.responseType) {
        cnf.responseType = 'implicit';
        cnf.includeGrantedScopes = true;
      }
      provider = new IdentityProvider(id, cnf);
      Oauth2Identity.addProvider(provider);
    }
    provider.userAgent = Oauth2Identity.userAgent;
    return provider;
  }
}
