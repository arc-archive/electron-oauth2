import { AuthorizationOptions, TokenInfo, TokenRemoveOptions } from '../lib/provider';

/**
 * Class responsible for handing OAuth2 related events and to pass them to
 * the main script for futher processing.
 */
export declare class OAuth2Handler {
  _requestId: number;
  _activeIds: object;
  constructor();

  /**
   * Attaches listeners on the body element to listen for elements events.
   */
  listen(): void;

  /**
   * Removes any event listeners registered by this class.
   */
  unlisten(): void;

  /**
   * Requests for a token from the main process.
   * @param opts Auth options.
   * @returns The token info object.
   */
  requestToken(opts: AuthorizationOptions): Promise<TokenInfo>;

  /**
   * Handler for the `oauth2-launchwebflow` custom event.
   * This sets a promise on the `detail.result` object instead of
   * dispatching event with the token.
   *
   * @param {} e
   */
  _launchFlowHandler(e: CustomEvent): void;

  /**
   * Handler for the `oauth2-token-requested` custom event.
   *
   * @param e Request custom event.
   */
  _tokenRequestedHandler(e: CustomEvent): void;

  /**
   * Prepares OAuth 2 config from the event detail.
   * @param detail Event's detail object
   */
  _prepareEventDetail(detail: object): AuthorizationOptions;

  /**
   * Handler for the `oauth2-token-remove` custom event dispatched to
   * clear cached token info.
   *
   * The event's `detail` object is optional. When it is set and contains both
   * `clientId` and `authorizationUri` this data will be used to create
   * identity provider.
   * Otherwise it will use `package.json` file to get oauth configuration.
   * @param {CustomEvent} e
   */
  _tokenRemoveHandler(e: CustomEvent): void;

  /**
   * Handler for the `oauth2-removetoken` custom event dispatched to
   * clear cached token info.
   *
   * It adds `result` on the detail object with the promise with the result of
   * removing the token.,
   * Configuration options are optional. When set and contains both
   * `clientId` and `authorizationUri` this data will be used to create
   * identity provider. Otherwise it uses `package.json` file to get oauth configuration.
   * @param {CustomEvent} e
   */
  _tokenPromiseRemoveHandler(e: CustomEvent): void;

  /**
   * Removes token from the chache.
   */
  deleteToken(opts?: TokenRemoveOptions): Promise<void>;

  /**
   * Generates `state` parameter for the OAuth2 call.
   *
   * @returns Generated state string.
   */
  generateState(): string;

  /**
   * Fires custom event.
   *
   * @param type Event name
   * @param detail Value of the detail object.
   */
  fire(type: string, detail?: object): void;

  /**
   * Checks if given ID is on the active IDs lis, removes the ID from the list
   * and returns initial options for the request.
   *
   * @param id ID given back from the main process.
   * @returns Request settings or undefined if not found
   */
  _checkAndRemoveRequestId(id: number): Object|undefined;

  /**
   * Handler for the token error response.
   *
   * @param e Renderer event
   * @param cause Error info.
   * @param id Generated and sent to main process ID
   */
  _tokenErrorHandler(e: Electron.IpcRendererEvent, cause: object, id: number): void;

  /**
   * Handler for succesful OAuth token request.
   *
   * @param e
   * @param tokenInfo Token info object
   * @param id Generated and sent to main process ID
   */
  _tokenReadyHandler(e: Electron.IpcRendererEvent, tokenInfo: TokenInfo, id: number): void;

  /**
   * Handler for oauth-2-token-removed main event.
   *
   * @param e
   * @param id Generated and sent to main process ID
   */
  _tokenRemovedHandler(e: Electron.IpcRendererEvent, id: number): void;
}
