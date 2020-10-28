/**
 * Authorization error object.
 */
export declare class AuthError extends Error {
  /**
   * A message associated with the error
   */
  message: string;
  /**
   * Error code name
   */
  code: string;
  /**
   * The token request state parameter.
   */
  state: string;
  /**
   * Whether the token request was interactive.
   */
  interactive?: boolean;
  /**
   * @param message A message associated with the error
   * @param code Error code name
   * @param state The state parameter.
   */
  constructor(message: string, code: string, state?: string);
}
