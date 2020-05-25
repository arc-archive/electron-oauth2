import { IdentityProvider, TokenInfo, AuthorizationOptions, BaseOptions, TokenRemoveOptions } from './provider';
/**
 * Class that manages OAuth2 identities.
 */
export declare class Oauth2Identity {
  /**
   * Listens for the renderer process events related to OAuth provider.
   */
  static listen(): void;

  /**
   * Handler for the `oauth-2-get-token` event from the render process.
   * Lunches the default OAuth flow with properties read from the manifest file.
   *
   * @param e IPC event
   * @param options Oauth options.
   */
  static _getTokenHandler(e: Electron.IpcMainEvent, options: AuthorizationOptions): Promise<void>;

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param e IPC event
   * @param options Oauth options.
   * @returns Promise resolved to the token object.
   */
  static _handleTokenRequest(e: Electron.IpcMainEvent, options: AuthorizationOptions): Promise<TokenInfo>;

  /**
   * Handler for the `oauth-2-launch-web-flow` event from the render process.
   * Lunches OAuth flow in browser window.
   *
   * @param e IPC event
   * @param options Oauth options.
   * @param id Id generated in the renderer to recognize the request.
   */
  static _launchWebFlowHandler(e: Electron.IpcMainEvent, options: AuthorizationOptions, id: string): Promise<void>;

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param e IPC event
   * @param options Oauth options.
   * @returns Promise resolved to the token object.
   */
  static _handleLaunchWebFlow(e: Electron.IpcMainEvent, options: AuthorizationOptions): Promise<TokenInfo>;

  /**
   * Handler for the `oauth-2-remove-token` event from the render process.
   * Removes chaced token data and token info from provider.
   *
   * @param e IPC event
   * @param options Oauth options.
   * @param id Id generated in the renderer to recognize the request.
   */
  static _removeTokenHandler(e: Electron.IpcMainEvent, options: TokenRemoveOptions, id: string): Promise<void>;

  /**
   * Asynchonous communication with the rendered process using Promises API.
   * @param e IPC event
   * @param options Oauth options.
   */
  static _handleRemoveToken(e: Electron.IpcMainEvent, options: TokenRemoveOptions): Promise<void>;

  /**
   * Generates a provider ID as an identifier for an identity
   *
   * @param {string} authUri User authorization URI
   * @param {string} clientId Client ID
   * @return An ID to be used to identity a provider.
   */
  static _generateProviderId(authUri: string, clientId: string): string;

  /**
   * Adds a provider to the list of existing (cached) providers.
   *
   * @param provider Provider to cache.
   */
  static _addProvider(provider: IdentityProvider): void;

  /**
   * Looks for existing OAuth provider with (possibly) cached auth data.
   *
   * @param authUri Authorization URL
   * @param clientId Client ID used to authenticate.
   * @returns An identity provider or `undefined` if not exists.
   */
  static _getProvider(authUri: string, clientId: string): IdentityProvider;

  /**
   * Runs the web authorization flow.
   * @param {} opts Authorization options
   * @returns A promise with auth result.
   */
  static launchWebAuthFlow(opts: AuthorizationOptions): Promise<TokenInfo>;

  /**
   * A method to call to authorize the user in Google authorization services.
   *
   * @param opts Authorization options
   * @returns A promise resulted to the auth token.
   */
  static getAuthToken(opts: BaseOptions): Promise<TokenInfo>;

  /**
   * Removes cached token info.
   *
   * @param opts When provided it is the same as for
   * `launchWebAuthFlow()` function. When not set it reads `package.json`
   * object for oauth2 configuration.
   */
  static removeToken(opts?: TokenRemoveOptions): Promise<void>;

  /**
   * Reads the default OAuth configuration for the app from package file.
   *
   * @returns A promise resolved to OAuth2 configuration object
   */
  static getOAuthConfig(): Promise<AuthorizationOptions>;

  /**
   * Returns chached provider or creates new provider based on the oauth
   * configuration.
   *
   * @param oauthConfig OAuth2 configuration object.
   * @returns Identity provider for given config.
   */
  static _getOrCreateProvider(oauthConfig: AuthorizationOptions): IdentityProvider;
}
