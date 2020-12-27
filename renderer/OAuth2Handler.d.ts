import { OAuth2AuthorizeEvent, OAuth2RemoveTokenEvent } from '@advanced-rest-client/arc-events';
import { OAuth2Authorization, TokenInfo, TokenRemoveOptions } from '@advanced-rest-client/arc-types/src/authorization/Authorization';

export declare const authorizeHandler: unique symbol;
export declare const removeTokenHandler: unique symbol;
export declare const prepareEventDetail: unique symbol;

/**
 * Class responsible for handing OAuth2 related events and to pass them to
 * the main script for further processing.
 */
export declare class OAuth2Handler {
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
  requestToken(opts: OAuth2Authorization): Promise<TokenInfo>;

  /**
   * Prepares OAuth 2 config from the event detail.
   * @param detail Event's detail object
   */
  [prepareEventDetail](detail: OAuth2Authorization): OAuth2Authorization;

  /**
   * Removes token from the cache.
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
   * Handler for the `oauth2-launchwebflow` custom event.
   * This sets a promise on the `detail.result` object instead of
   * dispatching event with the token.
   */
  [authorizeHandler](e: OAuth2AuthorizeEvent): void;

  /**
   * Handler for the `oauth2-removetoken` custom event dispatched to
   * clear cached token info.
   *
   * It adds `result` on the detail object with the promise with the result of
   * removing the token.,
   * Configuration options are optional. When set and contains both
   * `clientId` and `authorizationUri` this data will be used to create
   * identity provider. Otherwise it uses `package.json` file to get oauth configuration.
   */
  [removeTokenHandler](e: OAuth2RemoveTokenEvent): void;
}
