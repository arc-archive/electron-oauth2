/* eslint-disable require-jsdoc */
/* eslint-disable max-classes-per-file */
/**
 * An object describing an error during the authorization process.
 */
export class AuthorizationError extends Error {
  /**
   * @param {string} message The human readable message.
   * @param {string} code The error code
   * @param {string} state Used state parameter
   * @param {boolean} interactive Whether the request was interactive.
   */
  constructor(message, code, state, interactive) {
    super(message);
    this.code = code;
    this.state = state;
    this.interactive = interactive;
  }
}

export class CodeError extends Error {
  /**
   * @param {string} message The human readable message.
   * @param {string} code The error code
   */
  constructor(message, code) {
    super(message);
    this.code = code;
  }
}
