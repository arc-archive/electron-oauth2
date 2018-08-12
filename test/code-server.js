const {TestBaseServer} = require('./base-test-server');

class CodeServer extends TestBaseServer {
  constructor() {
    super();
    this.token = 'test-code-token';
    this.tokenType = 'test-code-type';
    this.code = 'test-code-response';
    this.expiresIn = 2700;
    this.responseType = 'code';
    this.refreshToken = 'code-refresh-token';
  }
}

const instance = new CodeServer();

module.exports = {
  create: function() {
    return instance.create();
  },
  shutdown: function() {
    return instance.shutdown();
  }
};
