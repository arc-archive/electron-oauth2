// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const assert = require('chai').assert;
const {IdentityProvider} = require('../');
const srv = require('./code-server');

describe('Code requests - main process', function() {
  this.timeout(10000);
  const ID = 'test-instance-id-code-request';
  const clientId = 'test-client-id-code-request';
  const scopes = ['code1', 'code1'];
  const responseType = 'authorization_code';
  const clientSecret = 'test-client-code-secret';
  const expectedToken = 'test-code-token';
  const expectedTokenType = 'test-code-type';
  const expectedRefreshToken = 'code-refresh-token';
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
        client_secret: clientSecret,
        redirect_uri: `http://localhost:${serverPort}/auth/popup`,
        auth_uri: `http://localhost:${serverPort}/auth`,
        token_uri: `http://localhost:${serverPort}/token`,
        scopes: scopes
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', function() {
      return instance.launchWebAuthFlow()
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.equal(tokenInfo.access_token, expectedToken);
        assert.equal(tokenInfo.accessToken, expectedToken);
        assert.equal(tokenInfo.tokenType, expectedTokenType);
        assert.equal(tokenInfo.token_type, expectedTokenType);
        assert.equal(tokenInfo.expiresIn, 2700);
        assert.equal(tokenInfo.expires_in, 2700);
        assert.typeOf(tokenInfo.expiresAt, 'number');
        assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
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
        assert.equal(tokenInfo.accessToken, 'test-code-token');
      });
    });

    it('Result with error when interactive and no session', function(done) {
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

    it('Handles application/x-www-form-urlencoded response data', function() {
      return instance.launchWebAuthFlow({
        customData: {
          token: {
            headers: [{
              name: 'accept',
              value: 'application/x-www-form-urlencoded'
            }]
          }
        }
      })
      .then((info) => {
        assert.typeOf(info, 'object');
        assert.equal(info.access_token, 'test-code-token');
        assert.equal(info.accessToken, info.access_token);
        assert.equal(info.tokenType, expectedRefreshToken);
        assert.equal(info.tokenType, info.token_type);
        assert.equal(info.expiresIn, 2700);
        assert.equal(info.expiresIn, info.expires_in);
        assert.typeOf(info.expiresAt, 'number');
      });
    });

    it('Sends custom query parameetrs', function() {
      return instance.launchWebAuthFlow({
        customData: {
          token: {
            parameters: [{
              name: 'custom_test_url',
              value: 'true'
            }],
            body: [{
              name: 'custom_test_url',
              value: 'true'
            }]
          }
        }
      })
      .then((info) => {
        assert.equal(info.custom_test_url, true);
      });
    });

    it('Sends custom headers', function() {
      return instance.launchWebAuthFlow({
        customData: {
          token: {
            headers: [{
              name: 'x-custom-test-headers',
              value: 'true'
            }],
            body: [{
              name: 'custom_test_headers',
              value: 'true'
            }]
          }
        }
      })
      .then((info) => {
        assert.typeOf(info, 'object');
        assert.equal(info.custom_test_headers, true);
      });
    });

    it('Sends custom body parameetrs', function() {
      return instance.launchWebAuthFlow({
        customData: {
          token: {
            body: [{
              name: 'custom_test_body',
              value: 'true'
            }]
          }
        }
      })
      .then((info) => {
        assert.equal(info.custom_test_body, true);
      });
    });
  });
});
