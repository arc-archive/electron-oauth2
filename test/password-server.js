const {TestBaseServer} = require('./base-test-server');

class PasswordServer extends TestBaseServer {
  constructor() {
    super();
    this.token = 'test-password-token';
    this.tokenType = 'test-password-type';
    this.code = 'test-password-response';
    this.expiresIn = 900;
    this.responseType = 'password-bearer';
    this.refreshToken = 'password-refresh-token';
  }
}

const instance = new PasswordServer();

module.exports = {
  create: function() {
    return instance.create();
  },
  shutdown: function() {
    return instance.shutdown();
  }
};
