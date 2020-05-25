const { TestBaseServer } = require('./base-test-server');

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
  create() {
    return instance.create();
  },
  shutdown() {
    return instance.shutdown();
  },
};
