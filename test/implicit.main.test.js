// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const assert = require('chai').assert;
const {IdentityProvider} = require('../');
const srv = require('./implicit-server.js');

describe('Implicit requests - main process', function() {
  this.timeout(10000);
  const ID = 'test-instance-id';
  const clientId = 'test-client-id';
  const scopes = ['test1', 'test2'];
  const responseType = 'implicit';
  let serverPort;
  before(() => {
    return srv.create()
    .then((port) => serverPort = port);
  });

  after(() => {
    return srv.shutdown();
  });

  describe('launchWebAuthFlow()', function() {
    let instance;
    let params;
    before(function() {
      params = {
        response_type: responseType,
        client_id: clientId,
        redirect_uri: `http://localhost:${serverPort}/auth/popup`,
        auth_uri: `http://localhost:${serverPort}/auth`,
        scopes: scopes
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', function() {
      return instance.launchWebAuthFlow()
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.equal(tokenInfo.accessToken, 'test-token');
        assert.equal(tokenInfo.accessToken, tokenInfo.access_token);
        assert.equal(tokenInfo.tokenType, 'bearer');
        assert.equal(tokenInfo.tokenType, tokenInfo.token_type);
        assert.equal(tokenInfo.expiresIn, 1800);
        assert.equal(tokenInfo.expiresIn, tokenInfo.expires_in);
        assert.typeOf(tokenInfo.expiresAt, 'number');
        assert.deepEqual(tokenInfo.scope, ['test1', 'test2']);
      });
    });

    it('Clears the browser window after finish', function() {
      return instance.launchWebAuthFlow()
      .then(() => {
        assert.isUndefined(instance.currentOAuthWindow);
        const {BrowserWindow} = require('electron');
        const wins = BrowserWindow.getAllWindows();
        assert.lengthOf(wins, 0);
      });
    });

    it('Handles errors', function(done) {
      instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_report_error',
              value: 'true'
            }]
          }
        }
      })
      .then(() => {
        done(new Error('Request is a success'));
      })
      .catch((cause) => {
        assert.equal(cause.code, 'test-error');
        assert.equal(cause.message, 'test-error-message');
        assert.isUndefined(cause.interactive);
        assert.typeOf(cause.state, 'string');
        done();
      });
    });

    it('Supports interactive state', function() {
      const rsult = instance.launchWebAuthFlow({
        interactive: false
      });
      assert.isFalse(instance.currentOAuthWindow.isVisible());
      return rsult
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.equal(tokenInfo.accessToken, 'test-token');
        assert.equal(tokenInfo.accessToken, tokenInfo.access_token);
        assert.equal(tokenInfo.tokenType, 'bearer');
        assert.equal(tokenInfo.tokenType, tokenInfo.token_type);
        assert.equal(tokenInfo.expiresIn, 1800);
        assert.equal(tokenInfo.expiresIn, tokenInfo.expires_in);
        assert.typeOf(tokenInfo.expiresAt, 'number');
        assert.deepEqual(tokenInfo.scope, ['test1', 'test2']);
      });
    });

    it('Results with error when interactive and no session', function(done) {
      instance.launchWebAuthFlow({
        interactive: false,
        customData: {
          auth: {
            parameters: [{
              name: 'custom_no_session',
              value: 'true'
            }]
          }
        }
      })
      .catch((info) => {
        assert.equal(info.code, 'auth_error');
        assert.equal(info.message, 'No response from the server.');
        assert.typeOf(info.state, 'string');
        done();
      });
    });

    it('Reports received from the server scopes', function() {
      return instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_scope',
              value: 'true'
            }]
          }
        }
      })
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.deepEqual(tokenInfo.scope, ['test1', 'test2', 'scope1', 'scope2']);
      });
    });

    it('Store token in cache store', function() {
      let info;
      return instance.launchWebAuthFlow()
      .then((tokenInfo) => {
        info = tokenInfo;
        return instance.restoreTokenInfo();
      })
      .then((restored) => {
        assert.typeOf(restored, 'object');
        assert.equal(restored.accessToken, info.accessToken);
        assert.equal(restored.access_token, info.access_token);
        assert.equal(restored.tokenType, info.tokenType);
        assert.equal(restored.token_type, info.token_type);
        assert.equal(restored.expiresIn, info.expiresIn);
        assert.equal(restored.expires_in, info.expires_in);
        assert.equal(restored.expiresAt, info.expiresAt);
        assert.deepEqual(restored.scope, info.scope);
      });
    });

    it('Waits until page is redirected', function() {
      return instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_delay_response',
              value: 'true'
            }]
          }
        }
      })
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
      });
    });

    it('Reports an error when window is closed without response', function(done) {
      const result = instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_no_session',
              value: 'true'
            }]
          }
        }
      });
      setTimeout(() => {
        instance.currentOAuthWindow.destroy();
      }, 1500);
      result.catch((info) => {
        assert.equal(info.code, 'user_interrupted');
        assert.equal(info.message, 'The request has been canceled by the user.');
        assert.typeOf(info.state, 'string');
        done();
      });
    });
  });
});
