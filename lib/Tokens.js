/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OidcTokenInfo} OidcTokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OidcTokenError} OidcTokenError */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenInfo} TokenInfo */

/**
 * Creates OIDC tokens.
 */
export class Tokens {
  /**
   * Creates a OidcTokenInfo object for the corresponding response type.
   *
   * @param {string} responseType The response type of the token to prepare the info for.
   * @param {URLSearchParams} params params received from the authorization endpoint.
   * @param {number} time Timestamp when the tokens were created
   * @param {string[]=} requestedScopes The list of requested scopes. Optional.
   * @return {OidcTokenInfo}
   */
  static createTokenInfo(responseType, params, time, requestedScopes) {
    switch (responseType) {
      case 'code': return Tokens.createCodeToken(params, time, requestedScopes);
      case 'token': return Tokens.createTokenToken(params, time, requestedScopes);
      case 'id_token': return Tokens.createIdTokenToken(params, time, requestedScopes);
      default: return null;
    }
  }

  /**
   * Creates a "code" response type token info.
   * @param {URLSearchParams} params
   * @param {number} time Timestamp when the tokens were created
   * @param {string[]=} requestedScopes The list of requested scopes. Optional.
   * @return {OidcTokenInfo}
   */
  static createBaseToken(params, time, requestedScopes) {
    const scope = Tokens.computeTokenInfoScopes(requestedScopes, params.get('scope'));
    const tokenInfo = /** @type OidcTokenInfo */ ({
      state: params.get('state'),
      expiresIn: Number(params.get('expires_in')),
      tokenType: params.get('token_type'),
      scope,
      time,
    });
    return tokenInfo;
  }

  /**
   * Creates a "code" response type token info.
   * @param {URLSearchParams} params
   * @param {number} time Timestamp when the tokens were created
   * @param {string[]=} requestedScopes The list of requested scopes. Optional.
   * @return {OidcTokenInfo}
   */
  static createCodeToken(params, time, requestedScopes) {
    const token = Tokens.createBaseToken(params, time, requestedScopes);
    token.responseType = 'code';
    token.code = params.get('code');
    return token;
  }

  /**
   * Creates a "token" response type token info.
   * @param {URLSearchParams} params
   * @param {number} time Timestamp when the tokens were created
   * @param {string[]=} requestedScopes The list of requested scopes. Optional.
   * @return {OidcTokenInfo}
   */
  static createTokenToken(params, time, requestedScopes) {
    const token = Tokens.createBaseToken(params, time, requestedScopes);
    token.responseType = 'token';
    token.accessToken = params.get('access_token');
    token.refreshToken = params.get('refresh_token');
    return token;
  }

  /**
   * Creates a "id_token" response type token info.
   * @param {URLSearchParams} params
   * @param {number} time Timestamp when the tokens were created
   * @param {string[]=} requestedScopes The list of requested scopes. Optional.
   * @return {OidcTokenInfo}
   */
  static createIdTokenToken(params, time, requestedScopes) {
    const token = Tokens.createBaseToken(params, time, requestedScopes);
    token.responseType = 'id_token';
    token.accessToken = params.get('access_token');
    token.refreshToken = params.get('refresh_token');
    token.idToken = params.get('id_token');
    return token;
  }

  /**
   * Computes the final list of granted scopes.
   * It is a list of scopes received in the response or the list of requested scopes.
   * Because the user may change the list of scopes during the authorization process
   * the received list of scopes can be different than the one requested by the user.
   *
   * @param {string[]} requestedScopes The list of requested scopes. Optional.
   * @param {string} tokenScopes The `scope` parameter received with the response. It's null safe.
   * @return {string[]} The list of scopes for the token.
   */
  static computeTokenInfoScopes(requestedScopes, tokenScopes) {
    if (!tokenScopes && requestedScopes) {
      return requestedScopes;
    }
    let listScopes = [];
    if (typeof tokenScopes === 'string') {
      listScopes = tokenScopes.split(' ');
    }
    return listScopes;
  }

  /**
   * @param {TokenInfo} info
   * @return {OidcTokenInfo}
   */
  static fromTokenInfo(info) {
    const result = /** @type OidcTokenInfo */ ({
      responseType: '',
      state: info.state,
      accessToken: info.accessToken,
      time: Date.now(),
    });
    if (info.scope) {
      result.scope = info.scope;
    }
    if (info.tokenType) {
      result.tokenType = info.tokenType;
    }
    if (info.expiresIn) {
      result.expiresIn = info.expiresIn;
    }
    return result;
  }
}
