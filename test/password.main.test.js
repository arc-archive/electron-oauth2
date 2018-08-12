// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const assert = require('chai').assert;
const {IdentityProvider} = require('../');
const srv = require('./password-server');

describe('Password requests - main process', function() {
  this.timeout(10000);
  const ID = 'test-instance-id-password-request';
  const clientId = 'test-client-id-password-request';
  const scopes = ['password1', 'password1'];
  const responseType = 'password';
  const username = 'test-user';
  const password = 'test-pwd';
  const expectedToken = 'test-password-token';
  const expectedTokenType = 'test-password-type';
  const expectedRefreshToken = 'password-refresh-token';
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
        token_uri: `http://localhost:${serverPort}/token`,
        scopes: scopes
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', function() {
      return instance.launchWebAuthFlow({
        username: username,
        password: password
      })
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.equal(tokenInfo.access_token, expectedToken);
        assert.equal(tokenInfo.accessToken, expectedToken);
        assert.equal(tokenInfo.tokenType, expectedTokenType);
        assert.equal(tokenInfo.token_type, expectedTokenType);
        assert.equal(tokenInfo.expiresIn, 900);
        assert.equal(tokenInfo.expires_in, 900);
        assert.typeOf(tokenInfo.expiresAt, 'number');
        assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
      });
    });

    it('Handles errors', function(done) {
      instance.launchWebAuthFlow({
        username: username,
        password: password,
        customData: {
          token: {
            body: [{
              name: 'custom_fail_request',
              value: 'true'
            }]
          }
        }
      })
      .then(() => {
        done(new Error('Request is a success'));
      })
      .catch((cause) => {
        setTimeout(() => {
          assert.equal(cause.code, 'uri_error');
          done();
        }, 1);
      });
    });

    it('Store token in cache store', function() {
      let info;
      return instance.launchWebAuthFlow({
        username: username,
        password: password,
      })
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

    it('Handles application/x-www-form-urlencoded response data', function() {
      return instance.launchWebAuthFlow({
        username: username,
        password: password,
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
        assert.equal(info.access_token, expectedToken);
        assert.equal(info.accessToken, expectedToken);
        assert.equal(info.tokenType, expectedTokenType);
        assert.equal(info.token_type, expectedTokenType);
        assert.equal(info.expiresIn, 900);
        assert.equal(info.expires_in, 900);
        assert.typeOf(info.expiresAt, 'number');
        assert.equal(info.refreshToken, expectedRefreshToken);
      });
    });

    it('Sends custom query parameetrs', function() {
      return instance.launchWebAuthFlow({
        username: username,
        password: password,
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
        username: username,
        password: password,
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
        username: username,
        password: password,
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
