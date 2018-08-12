const {TestBaseServer} = require('./base-test-server');

class ImplicitServer extends TestBaseServer {
  constructor() {
    super();
    this.token = 'test-token';
    this.expiresIn = 1800;
    this.responseType = 'token';
  }
}

const instance = new ImplicitServer();

module.exports = {
  create: function() {
    return instance.create();
  },
  shutdown: function() {
    return instance.shutdown();
  }
};
