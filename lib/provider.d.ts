import { BrowserWindow } from 'electron';
import { URLSearchParams } from 'url';
import Store from 'electron-store';
import { AuthError } from './AuthError';
import { OAuth2Authorization } from '@advanced-rest-client/arc-types/src/authorization/Authorization';
import { TokenInfo } from '@advanced-rest-client/arc-types/src/oauth2/OAuth2';

declare interface CodeResponseObject {
  /**
   * Response status
   */
  status: number;
  /**
   * Response headers
   */
  headers: object;
  /**
   * Response body
   */
  body: string;
}


/**
 * A class to perform OAuth2 flow with given configuration.
 */
export class IdentityProvider {
  /**
   * The user agent to be set on the browser window when requesting for a token
   * in a browser flow. This allows to fix the issue with Google auth servers that
   * stopped supporting default electron user agent.
   */
  userAgent: string;
  /**
   * Generated ID for the provider.
   */
  id: string;
  /**
   * OAuth2 configuration for this provider.
   * If not set the settings argument from calling oauth flow function must
   * contain all properties.
   * This is configuration object used when the OAuth configuration is read
   * from the package.json file.
   */
  oauthConfig?: OAuth2Authorization;
  /**
   * In memory cached token data
   */
  tokenInfo?: TokenInfo;
  /**
   * Cached token key id in the persistent store.
   */
  cacheKey: string;
  /**
   * Latest generated state parameter for the request.
   * If the settings object when calling any of the request OAuth flow
   * methods has state parameter, it will be used.
   */
  _state: string;
  /**
   * Instance of the store library to cache token data.
   */
  tokenStore: Store;

  currentOAuthWindow: BrowserWindow;
  /**
   *
   * @param id ID of the provider.
   * @param oauthConfig OAuth2 configuration.
   */
  constructor(id: string, oauthConfig?: OAuth2Authorization);

  /**
   * Enables session in module's partition.
   */
  _startSession(): void;

  /**
   * Clears the state of the element.
   */
  clear(): void;

  /**
   * Clears token cache data and current token information.
   */
  clearCache(): void;

  /**
   * Gets either cached authorization token or request for new one.
   *
   * If the `interactive` flag is false the authorization prompt
   * window will never be opened and if the authorization scope has
   * changed or user did not authorized the application this will
   * result in Promise error.
   *
   * @param opts Authorization options
   * @returns A promise resulted to the auth token. It return undefined
   * if the app is not authorized. The promise will result with error (reject)
   * if there's an authorization error.
   */
  getAuthToken(opts?: OAuth2Authorization): Promise<TokenInfo>|undefined;

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
   * The server uses the hint to simplify the login flow either by pre-filling
   * the email field in the sign-in form or by selecting the appropriate
   * multi-login session. Set the parameter value to an email address or `sub`
   * identifier.
   * @returns A promise with auth result.
   */
  launchWebAuthFlow(opts?: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Browser or server flow: open the initial popup.
   * @param settings Settings passed to the authorize function.
   * @param type `token` or `code`
   * @returns Full URL for the endpoint.
   */
  _constructPopupUrl(settings: OAuth2Authorization, type: string): string;

  /**
   * Computes `scope` URL parameter from scopes array.
   *
   * @param scopes List of scopes to use with the request.
   * @returns Computed scope value.
   */
  _computeScope(scopes: string[]): string;

  /**
   * Authorizes the user in the OAuth authorization endpoint.
   * By default it authorizes the user using a popup that displays
   * authorization screen. When `interactive` property is set to `false`
   * on the `settings` object then it will not render `BrowserWindow`.
   *
   * @param authUrl Complete authorization url
   * @param settings Passed user settings
   */
  _authorize(authUrl: string, settings: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Adds listeners to a window object.
   *
   * @param win Window object to observe events on.
   */
  _observeAuthWindowNavigation(win: BrowserWindow): void;

  /**
   * Removes event listeners, closes the window and cleans the property.
   */
  unobserveAuthWindow(): void;

  /**
   * Reports authorization error back to the application.
   *
   * This operation clears the promise object.
   *
   * @param error Error details to report to the app.
   * It should contain `code` and `message` properties.
   */
  _reportOAuthError(error: AuthError): void;

  /**
   * Parses response URL and reports the result of the request.
   *
   * @param url Redirected response URL
   */
  _reportOAuthResult(url: string): void;

  /**
   * Processes OAuth2 server query string response.
   *
   * @param oauthParams Created from parameters params.
   */
  _processPopupResponseData(oauthParams: URLSearchParams): void;

  /**
   * Creates a token info object from query parameters
   */
  _tokenInfoFromParams(oauthParams: URLSearchParams): TokenInfo;

  /**
   * Computes the final list of granted scopes.
   * It is a list of scopes received in the response or the list of requested scopes.
   * Because the user may change the list of scopes during authorization
   * the received list of scopes can be different than the one requested by the user.
   *
   * @param scope The `scope` parameter received with the response. May be
   * `undefined`.
   * @returns The list of scopes for the token.
   */
  _computeTokenInfoScopes(scope: string): string[]|undefined;

  /**
   * Resolves the main promise with token data.
   * @param info Auth token information
   */
  _handleTokenInfo(info: TokenInfo): void;

  /**
   * Handler fore an error that happened during code exchange.
   */
  _handleTokenCodeError(e: Error): void;

  /**
   * Exchange code for token.
   *
   * @param code Returned code from the authorization endpoint.
   */
  _exchangeCode(code: string): Promise<void>;

  /**
   * Returns a body value for the code exchange request.
   * @param settings Initial settings object.
   * @param code Authorization code value returned by the authorization
   * server.
   * @returns Request body.
   */
  _getCodeExchangeBody(settings: OAuth2Authorization, code: string): string;

  /**
   * Camel case given name.
   *
   * @param name Value to camel case.
   * @returns Camel cased name
   */
  _camel(name: string): string|undefined

  /**
   * Requests for token from the authorization server for `code`, `password`,
   * `client_credentials` and custom grant types.
   *
   * @param url Base URI of the endpoint. Custom properties will be
   * applied to the final URL.
   * @param body Generated body for given type. Custom properties will
   * be applied to the final body.
   * @param settings Settings object passed to the `authorize()`
   * function
   * @returns Promise resolved to the response string.
   */
  _requestToken(url: string, body: string, settings: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Handler for the code request error event.
   * Rejects the promise with error description.
   *
   * @param error An error object
   * @param reject Promise's reject function.
   */
  _processTokenResponseErrorHandler(error: Error, reject: Function): void;

  /**
   * Handler for the code request load event.
   * Processes the response and either rejects the promise with an error
   * or resolves it to token info object.
   *
   * @param response A response containing `status` and `body  `
   * @param resolve Resolve function
   * @param reject Reject function
   */
  _processTokenResponseHandler(response: CodeResponseObject, resolve: Function, reject: Function): void;

  /**
   * Processes token request body and produces map of values.
   *
   * @param body Body received in the response.
   * @param contentType Response content type.
   * @returns Response as an object.
   * @throws {Error} Exception when body is invalid.
   */
  _processCodeResponse(body: string, contentType: string): TokenInfo;

  /**
   * Applies custom properties defined in the OAuth settings object to the URL.
   *
   * @param url Generated URL for an endpoint.
   * @param data `customData.[type]` property from the settings object.
   * The type is either `auth` or `token`.
   */
  _applyCustomSettingsQuery(url: string, data: object): string;

  /**
   * Applies custom headers from the settings object
   *
   * @param request Instance of the request object.
   * @param data Value of settings' `customData` property
   */
  _applyCustomSettingsHeaders(request: Electron.ClientRequest, data: Object): void;

  /**
   * Applies custom body properties from the settings to the body value.
   *
   * @param body Already computed body for OAuth request. Custom
   * properties are appended at the end of OAuth string.
   * @param data Value of settings' `customData` property
   * @returns Request body
   */
  _applyCustomSettingsBody(body: string, data: object): string;

  /**
   * Requests a token for `password` request type.
   *
   * @param settings The same settings as passed to `authorize()`
   * function.
   * @returns Promise resolved to token info.
   */
  authorizePassword(settings: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Generates a payload message for password authorization.
   *
   * @param {Object} settings Settings object passed to the `authorize()`
   * function
   * @return {string} Message body as defined in OAuth2 spec.
   */
  _getPasswordBody(settings: OAuth2Authorization): string;

  /**
   * Requests a token for `client_credentials` request type.
   *
   * @param settings The same settings as passed to `authorize()`
   * function.
   * @returns Promise resolved to a token info object.
   */
  authorizeClientCredentials(settings: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Generates a payload message for client credentials.
   *
   * @param {Object} settings Settings object passed to the `authorize()`
   * function
   * @return {String} Message body as defined in OAuth2 spec.
   */
  _getClientCredentialsBody(settings: OAuth2Authorization): string;

  /**
   * Performs authorization on custom grant type.
   * This extension is described in OAuth 2.0 spec.
   *
   * @param settings Settings object as for `authorize()` function.
   * @returns Promise resolved to a token info object.
   */
  authorizeCustomGrant(settings: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Creates a body for custom gran type.
   * It does not assume any parameter to be required.
   * It applies all known OAuth 2.0 parameters and then custom parameters
   *
   * @param settings Settings object as for `authorize()` function.
   * @returns Request body.
   */
  _getCustomGrantBody(settings: OAuth2Authorization): string;

  /**
   * Creates an error object to be reported back to the app.
   * @param oauthParams Map of oauth response parameters
   * @returns Error object.
   */
  _createResponseError(oauthParams: Object): AuthError;

  /**
   * Handler for the auth window close event.
   * If the response wasn't reported so far it reports error.
   */
  _authWindowCloseHandler(): void;

  /**
   * A handler for `onComplete` of session's webRequest object.
   */
  _sessionCompletedListener(detail: Object): void;

  /**
   * Checks if current token is authorized for given list of scopes.
   *
   * @param tokenInfo A token info object.
   * @param scopes List of scopes to authorize.
   * @returns True if requested scope is already authorized with this
   * token.
   */
  isTokenAuthorized(tokenInfo: TokenInfo, scopes: string[]): boolean;

  /**
   * Returns cached token info.
   *
   * @returns Token info object or `undefined` if there's
   * no cached token or cached token expired.
   */
  getTokenInfo(): Promise<TokenInfo>;

  /**
   * Restores authorization token information from the local store.
   *
   * @returns Token info object or `undefined` if not set or expired.
   */
  restoreTokenInfo(): Promise<TokenInfo>

  /**
   * Caches token data in local storage.
   *
   * @param tokenInfo The token info object
   * @returns Resolved promise when code is executed
   */
  storeToken(tokenInfo: TokenInfo): Promise<void>;

  /**
   * Checks if the token already expired.
   *
   * @param tokenInfo Token info object
   * @returns True if the token is already expired and should be
   * renewed.
   */
  isExpired(tokenInfo: TokenInfo): boolean;

  /**
   * Computes token expiration time.
   * It sets `expires_at` property on the token info object which is the time
   * in the future when when the token expires.
   *
   * @param tokenInfo Token info object
   */
  computeExpires(tokenInfo: TokenInfo): void;

  /**
   * Generates a random string to be used as a `state` parameter, sets the
   * `_state` property to generated text and returns the value.
   *
   * @returns Generated state parameter.
   */
  randomString(): string;
}
