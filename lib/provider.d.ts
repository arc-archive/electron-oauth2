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
import { OAuth2Authorization, TokenInfo } from '@advanced-rest-client/arc-types/src/authorization/Authorization';
import { FetchResponse } from '../types.js';

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.TokenInfo} TokenInfo */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2CustomData} OAuth2CustomData */
/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2AuthorizationRequestCustomData} OAuth2AuthorizationRequestCustomData */
/** @typedef {import('./provider').CodeResponseObject} CodeResponseObject */
/** @typedef {import('../types').FetchResponse} FetchResponse */

export declare const authorize: unique symbol;
export declare const reportOAuthError: unique symbol;
export declare const authorizeImplicitCode: unique symbol;
export declare const authWindowCloseHandler: unique symbol;
export declare const observeAuthWindowNavigation: unique symbol;
export declare const sessionErrorListener: unique symbol;
export declare const sessionCompletedListener: unique symbol;
export declare const processPopupRawData: unique symbol;
export declare const processTokenResponse: unique symbol;
export declare const createTokenResponseError: unique symbol;
export declare const createErrorParams: unique symbol;
export declare const handleTokenInfo: unique symbol;
export declare const tokenResponse: unique symbol;
export declare const tokenInfoFromParams: unique symbol;
export declare const computeTokenInfoScopes: unique symbol;
export declare const computeExpires: unique symbol;
export declare const processCodeResponse: unique symbol;
export declare const handleTokenCodeError: unique symbol;
export declare const authorizeClientCredentials: unique symbol;
export declare const authorizePassword: unique symbol;
export declare const authorizeCustomGrant: unique symbol;
export declare const startSession: unique symbol;
export declare const resolveFunction: unique symbol;
export declare const rejectFunction: unique symbol;

/**
 * A class to perform OAuth2 flow with given configuration.
 *
 * See README.md file for detailed description.
 */
export class IdentityProvider {
  /**
   * The code verifier used by the PKCE extension
   */
  #codeVerifier: string;

  /**
   * The current state parameter
   */
  #state: string;

  /**
   * The main resolve function
   */
  [resolveFunction]: (info: TokenInfo) => void;

  /**
   * The main reject function
   */
  [rejectFunction]: (error: Error) => void;

  /**
   * The final OAuth 2 settings to use.
   */
  #settings: OAuth2Authorization;

  /**
   * Instance of the store library to cache token data.
   */
  tokenStore: Store;

  #oauthWindowListening: boolean;

  /**
   * @type {NodeJS.Timeout}
   */
  #loadPopupTimeout: NodeJS.Timeout;

  /**
   * @type Electron.Session
   */
  #session: Electron.Session;

  /**
   * The request state parameter. If the state is not passed with the configuration one is generated.
   */
  get state(): string;

  /**
   * When PKCE extension is used, this holds the value of generated code verifier
   */
  get codeVerifier(): string;

  id: string;

  /**
   * OAuth2 configuration for this provider.
   * If not set the settings argument from calling oauth flow function must
   * contain all properties.
   * This is configuration object used when the OAuth configuration is read
   * from the package.json file.
   */
  oauthConfig: OAuth2Authorization;

  /**
   * The cached token key id in the persistent store.
   */
  cacheKey: string;

  /**
   * The user agent to be set on the browser window when requesting for a token
   * in a browser flow. This allows to fix the issue with Google auth servers that
   * stopped supporting default electron user agent.
   */
  userAgent: string;

  currentOAuthWindow?: Electron.BrowserWindow;

  /**
   * @param id ID of the provider.
   * @param oauthConfig OAuth2 configuration.
   */
  constructor(id: string, oauthConfig?: OAuth2Authorization);

  /**
   * Enables session in module's partition.
   */
  [startSession](): void;

  /**
   * Clears the state of the element.
   */
  clear(): void;

  /**
   * Clears token cache data and current token information.
   */
  clearCache(): void;

  /**
   * A function that should be called before the authorization.
   * It checks configuration integrity, and performs some sanity checks
   * like proper values of the request URIs.
   */
  checkConfig(): void;

  /**
   * Gets either cached authorization token or request for new one.
   *
   * If the `interactive` flag is false the authorization prompt
   * window will never be opened and if the authorization scope has
   * changed or user did not authorized the application this will
   * result in Promise error.
   *
   * @param settings Authorization options
   * @return A promise resulted to the auth token.
   * It return undefined if the app is not authorized. The promise will result
   * with error (reject) if there's an authorization error.
   */
  getAuthToken(settings?: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Runs the web authorization flow.
   * @param settings Authorization options
   * @return A promise with auth result.
   */
  launchWebAuthFlow(settings?: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Starts the authorization process.
   */
  [authorize](): void;

  /**
   * Starts the authorization flow for the `implicit` and `authorization_code` flows.
   * If the `interactive` flag is configured, then it won't show the window.
   */
  [authorizeImplicitCode](): Promise<void>;

  /**
   * Browser or server flow: open the initial popup.
   * @return Full URL for the endpoint.
   */
  constructPopupUrl(): Promise<string>;

  /**
   * Adds listeners to a window object.
   *
   * @param win Window object to observe events on.
   */
  [observeAuthWindowNavigation](win: Electron.BrowserWindow): void;

  /**
   * Removes event listeners, closes the window and cleans the property.
   */
  unobserveAuthWindow(): void;

  /**
   * Handler for the auth window close event.
   * If the response wasn't reported so far it reports error.
   */
  [authWindowCloseHandler](): void;

  /**
   * Reports authorization error back to the application.
   *
   * This operation clears the promise object.
   *
   * @param message The message to report
   * @param code Error code
   */
  [reportOAuthError](message: string, code?: string): void;

  /**
   * Parses response URL and reports the result of the request.
   *
   * @param url Redirected response URL
   */
  [processPopupRawData](url: string): void;

  /**
   * Processes OAuth2 server query string response.
   *
   * @param oauthParams Created from parameters params.
   */
  [processTokenResponse](oauthParams: URLSearchParams): Promise<void>;

  /**
   * Creates a token info object from query parameters
   */
  [tokenInfoFromParams](oauthParams: URLSearchParams): TokenInfo;

  /**
   * Computes the final list of granted scopes.
   * It is a list of scopes received in the response or the list of requested scopes.
   * Because the user may change the list of scopes during the authorization process
   * the received list of scopes can be different than the one requested by the user.
   *
   * @param scope The `scope` parameter received with the response. It's null safe.
   * @return {string[]} The list of scopes for the token.
   */
  [computeTokenInfoScopes](scope: string): string[];

  /**
   * Computes token expiration time.
   * It sets `expires_at` property on the token info object which is the time
   * in the future when when the token expires.
   *
   * @param tokenInfo Token info object
   * @return A copy with updated properties.
   */
  [computeExpires](tokenInfo: TokenInfo): TokenInfo

  /**
   * Processes token info object when it's ready.
   *
   * @param info Token info returned from the server.
   */
  [handleTokenInfo](info: TokenInfo): void;

  /**
   * Exchanges the authorization code for authorization token.
   *
   * @param code Returned code from the authorization endpoint.
   * @return The token info when the request was a success.
   */
  exchangeCode(code: string): Promise<TokenInfo>;

  /**
   * Returns a body value for the code exchange request.
   * @param code Authorization code value returned by the authorization server.
   * @return Request body.
   */
  getCodeRequestBody(code: string): string;

  /**
   * Requests for token from the authorization server for `code`, `password`, `client_credentials` and custom grant types.
   *
   * @param url Base URI of the endpoint. Custom properties will be applied to the final URL.
   * @param body Generated body for given type. Custom properties will be applied to the final body.
   * @return Promise resolved to the response string.
   */
  requestToken(url: string, body: string): Promise<TokenInfo>;

  fetchToken(url: string, headers: object, body: string): Promise<FetchResponse>;

  /**
   * Processes code response body and produces map of values.
   *
   * @param body Body received in the response.
   * @param mime Response content type.
   * @return Response as an object.
   * @throws {Error} Exception when the body is invalid.
   */
  [processCodeResponse](body: string, mime: string): TokenInfo;

  /**
   * A handler for the error that happened during code exchange.
   * @param {Error} e
   */
  [handleTokenCodeError](e: Error): void;

  /**
   * Requests a token for `client_credentials` request type.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return {Promise<void>} Promise resolved to a token info object.
   */
  [authorizeClientCredentials](): Promise<void>;

  /**
   * Generates a payload message for client credentials.
   *
   * @return Message body as defined in OAuth2 spec.
   */
  getClientCredentialsBody(): string;

  /**
   * Requests a token for `client_credentials` request type.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return {} Promise resolved to a token info object.
   */
  [authorizePassword](): Promise<void>;

  /**
   * Generates a payload message for password authorization.
   *
   * @return Message body as defined in OAuth2 spec.
   */
  getPasswordBody(): string;

  /**
   * Performs authorization on custom grant type.
   * This extension is described in OAuth 2.0 spec.
   *
   * This method resolves the main promise set by the `authorize()` function.
   *
   * @return Promise resolved when the request finish.
   */
  [authorizeCustomGrant](): Promise<void>;

  /**
   * Generates a payload message for the custom grant.
   *
   * @return Message body as defined in OAuth2 spec.
   */
  getCustomGrantBody(): string;

  /**
   * Processes the response returned by the popup or the iframe.
   * @param oauthParams
   * @return Parameters for the [reportOAuthError]() function
   */
  [createTokenResponseError](oauthParams: URLSearchParams): string[];

  /**
   * Creates arguments for the error function from error response
   * @param code Returned from the authorization server error code
   * @param description Returned from the authorization server error description
   * @return Parameters for the [reportOAuthError]() function
   */
  [createErrorParams](code: string, description?: string): string[];

  /**
   * A handler for `onComplete` of session's webRequest object.
   */
  [sessionCompletedListener](detail: Electron.OnCompletedListenerDetails): void;

  /**
   * A handler for the `onErrorOccurred` event of the session's webRequest object.
   */
  [sessionErrorListener](detail: Electron.OnErrorOccurredListenerDetails): void;

  /**
   * Checks if current token is authorized for given list of scopes.
   *
   * @param tokenInfo A token info object.
   * @param scopes List of scopes to authorize.
   * @return True if requested scope is already authorized with this token.
   */
  isTokenAuthorized(tokenInfo: TokenInfo, scopes: string[]): boolean;

  /**
   * Returns cached token info.
   *
   * @return Token info object or `undefined` if there's no cached token or cached token expired.
   */
  getTokenInfo(): Promise<TokenInfo|undefined>;

  /**
   * Restores authorization token information from the local store.
   *
   * @return Token info object or `undefined` if not set or expired.
   */
  restoreTokenInfo(): Promise<TokenInfo>;

  /**
   * Caches token data in local storage.
   *
   * @return Resolved promise when code is executed
   */
  storeToken(tokenInfo: TokenInfo): Promise<void>;

  /**
   * Checks if the token already expired.
   *
   * @param tokenInfo Token info object
   * @return True if the token is already expired and should be renewed.
   */
  isExpired(tokenInfo: TokenInfo): boolean;
}
