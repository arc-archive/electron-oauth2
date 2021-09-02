import i18n from 'i18n';
import { Tokens } from './Tokens.js';
import { IdentityProvider, grantResponseMapping, reportOAuthError, resolveFunction, rejectFunction, handleTokenInfo, authorize, settingsValue } from './IdentityProvider.js';
import { nonceGenerator } from './Utils.js';
import { AuthorizationError } from './AuthorizationError.js';

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OidcTokenInfo} OidcTokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OidcTokenError} OidcTokenError */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenInfo} TokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OidcAuthorization} OidcAuthorization */

/**
 * Identity provider that specializes in the OpenId Connect.
 */
export class OidcProvider extends IdentityProvider {
  /**
   * @return {Promise<URL>} The parameters to build popup URL.
   */
  async buildPopupUrlParams() {
    const url = await super.buildPopupUrlParams();
    const config = this[settingsValue];
    const type = /** @type string */ (config.responseType || grantResponseMapping[config.grantType]);
    // ID token nonce
    if (type.includes('id_token')) {
      url.searchParams.set('nonce', nonceGenerator());
    }
    return url;
  }

  /**
   * @param {URLSearchParams} params The instance of search params with the response from the auth dialog.
   * @return {boolean} true when the params qualify as an authorization popup redirect response.
   */
  validateTokenResponse(params) {
    if (params.has('id_token')) {
      return true;
    }
    // @ts-ignore
    return super.validateTokenResponse(params);
  }

  /**
   * Processes the response returned by the popup or the iframe.
   * @param {URLSearchParams} params
   */
  async processTokenResponse(params) {
    const state = params.get('state');
    if (!state) {
      this[reportOAuthError](i18n.__('ERR_SERVER_STATE'), 'no_state');
      return;
    }
    if (state !== this.state) {
      this[reportOAuthError](i18n.__('ERR_STATE_MISMATCH'), 'invalid_state');
      return;
    }
    if (params.has('error')) {
      // @ts-ignore
      const info = this.createTokenResponseError(params);
      // @ts-ignore
      this[reportOAuthError](...info);
      return;
    }
    // this is the time when the tokens are received. +- a few ms.
    const time = Date.now();
    const tokens = /** @type {(OidcTokenInfo|OidcTokenError)[]} */ (this.prepareTokens(params, time));
    if (!Array.isArray(tokens) || !tokens.length) {
      this[reportOAuthError](i18n.__('ERR_UNKNOWN_STATE'), 'unknown_state');
      return;
    }
    const codeIndex = tokens.findIndex((i) => i.responseType === 'code');
    if (codeIndex >= 0) {
      const codeToken = /** @type OidcTokenInfo */ (tokens[codeIndex]);
      try {
        const info = await this.getCodeInfo(codeToken.code);
        if (info.error) {
          tokens[codeIndex] = /** @type OidcTokenError */ {
            responseType: codeToken.responseType,
            state: codeToken.state,
            error: info.error,
            errorDescription: info.errorDescription,
          };
        } else {
          codeToken.accessToken = info.accessToken;
          codeToken.refreshToken = info.refreshToken;
          codeToken.idToken = info.idToken;
          codeToken.tokenType = info.tokenType;
          codeToken.expiresIn = info.expiresIn;
          codeToken.scope = Tokens.computeTokenInfoScopes(this[settingsValue].scopes, info.scope);
        }
      } catch (e) {
        tokens[codeIndex] = /** @type OidcTokenError */ {
          responseType: codeToken.responseType,
          state: codeToken.state,
          error: 'unknown_state',
          errorDescription: e.message,
        };
      }
    }
    this.finish(tokens);
  }

  /**
   * Creates a token info object for each requested response type. These are created from the params received from the
   * redirect URI. This means that it might not be complete (for code response type).
   * @param {URLSearchParams} params
   * @param {number} time Timestamp when the tokens were created
   * @return {OidcTokenInfo[]}
   */
  prepareTokens(params, time) {
    const { grantType, responseType='', scopes } = this[settingsValue];
    let type = responseType;
    if (!type) {
      type = grantResponseMapping[grantType];
    }
    if (!type) {
      return null;
    }
    const types = type.split(' ').map((i) => i.trim()).filter((i) => !!i);
    return types.map((item) => Tokens.createTokenInfo(item, params, time, scopes));
  }

  /**
   * Finishes the authorization.
   * @param {(OidcTokenInfo|OidcTokenError)[]} tokens
   */
  finish(tokens) {
    if (this[resolveFunction]) {
      // @ts-ignore
      this[resolveFunction](tokens);
    }
    this[rejectFunction] = undefined;
    this[resolveFunction] = undefined;
  }

  /**
   * Processes token info object when it's ready.
   *
   * @param {TokenInfo} info Token info returned from the server.
   */
  [handleTokenInfo](info) {
    const { responseType } = this[settingsValue];
    const token = Tokens.fromTokenInfo(info);
    token.responseType = responseType;
    this.finish([token]);
  }

  /**
   * @param {OidcAuthorization=} settings Authorization options
   * @return {Promise<(OidcTokenInfo|OidcTokenError)[]>}
   */
  async getAuthTokens(settings={}) {
    try {
      const list = await this.authorizeOidc(settings);
      return list;
    } catch (cause) {
      if (this[settingsValue].interactive === false) {
        return;
      }
      const err = new AuthorizationError(cause.message, cause.code, settings.state, false);
      throw err;
    }
  }

  /**
   * Runs the web authorization flow.
   * @param {OidcAuthorization=} settings Authorization options
   * @return {Promise<(OidcTokenInfo|OidcTokenError)[]>}
   */
  async authorizeOidc(settings={}) {
    this[settingsValue] = { ...this.oauthConfig, ...settings };
    this.checkConfig();
    return new Promise((resolve, reject) => {
      // @ts-ignore
      this[resolveFunction] = resolve;
      this[rejectFunction] = reject;
      this[authorize]();
    });
  }
}
