/**
 * Authorization error object.
 */
export class AuthError extends Error {
  /**
   * @param {string} message A message associated with the error
   * @param {string} code Error code name
   * @param {string=} state The state parameter.
   */
  constructor(message, code, state) {
    super(message);
    this.code = code;
    this.state = state;
    this.interactive = undefined;
  }
}
