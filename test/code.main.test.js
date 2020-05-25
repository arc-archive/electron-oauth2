// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const assert = require('chai').assert;
const { IdentityProvider } = require('../');
const srv = require('./code-server');

describe('Code requests - main process', () => {
  const ID = 'test-instance-id-code-request';
  const clientId = 'test-client-id-code-request';
  const scopes = ['code1', 'code1'];
  const responseType = 'authorization_code';
  const clientSecret = 'test-client-code-secret';
  const expectedToken = 'test-code-token';
  const expectedTokenType = 'test-code-type';
  const expectedRefreshToken = 'code-refresh-token';
  let serverPort;
  before(() => srv.create()
    .then((port) => serverPort = port));

  after(() => srv.shutdown());

  describe('launchWebAuthFlow()', () => {
    let instance;
    let params;
    before(() => {
      params = {
        response_type: responseType,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: `http://localhost:${serverPort}/auth/popup`,
        auth_uri: `http://localhost:${serverPort}/auth`,
        token_uri: `http://localhost:${serverPort}/token`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', () => instance.launchWebAuthFlow()
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
      }));

    it('Handles errors', (done) => {
      instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_report_error',
              value: 'true',
            }],
          },
        },
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

    it('Supports interactive state', () => {
      const rsult = instance.launchWebAuthFlow({
        interactive: false,
      });
      assert.isFalse(instance.currentOAuthWindow.isVisible());
      return rsult
        .then((tokenInfo) => {
          assert.typeOf(tokenInfo, 'object');
          assert.equal(tokenInfo.accessToken, 'test-code-token');
        });
    });

    it('Result with error when interactive and no session', (done) => {
      instance.launchWebAuthFlow({
        interactive: false,
        customData: {
          auth: {
            parameters: [{
              name: 'custom_no_session',
              value: 'true',
            }],
          },
        },
      })
        .catch((info) => {
          assert.equal(info.code, 'auth_error');
          assert.equal(info.message, 'No response from the server.');
          assert.typeOf(info.state, 'string');
          done();
        });
    });

    it('Store token in cache store', () => {
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

    it('Waits until page is redirected', async () => {
      const tokenInfo = await instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_delay_response',
              value: 'true',
            }],
          },
        },
      });
      assert.typeOf(tokenInfo, 'object');
    });

    it('Reports an error when window is closed without response', (done) => {
      const result = instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_no_session',
              value: 'true',
            }],
          },
        },
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

    it('Handles application/x-www-form-urlencoded response data', () => instance.launchWebAuthFlow({
      customData: {
        token: {
          headers: [{
            name: 'accept',
            value: 'application/x-www-form-urlencoded',
          }],
        },
      },
    })
      .then((tokenInfo) => {
        assert.typeOf(tokenInfo, 'object');
        assert.equal(tokenInfo.access_token, 'test-code-token');
        assert.equal(tokenInfo.access_token, expectedToken);
        assert.equal(tokenInfo.accessToken, expectedToken);
        assert.equal(tokenInfo.tokenType, expectedTokenType);
        assert.equal(tokenInfo.token_type, expectedTokenType);
        assert.equal(tokenInfo.expiresIn, 2700);
        assert.equal(tokenInfo.expires_in, 2700);
        assert.typeOf(tokenInfo.expiresAt, 'number');
        assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
      }));

    it('Sends custom query parameetrs', () => instance.launchWebAuthFlow({
      customData: {
        token: {
          parameters: [{
            name: 'custom_test_url',
            value: 'true',
          }],
          body: [{
            name: 'custom_test_url',
            value: 'true',
          }],
        },
      },
    })
      .then((info) => {
        assert.equal(info.custom_test_url, true);
      }));

    it('Sends custom headers', () => instance.launchWebAuthFlow({
      customData: {
        token: {
          headers: [{
            name: 'x-custom-test-headers',
            value: 'true',
          }],
          body: [{
            name: 'custom_test_headers',
            value: 'true',
          }],
        },
      },
    })
      .then((info) => {
        assert.typeOf(info, 'object');
        assert.equal(info.custom_test_headers, true);
      }));

    it('Sends custom body parameetrs', () => instance.launchWebAuthFlow({
      customData: {
        token: {
          body: [{
            name: 'custom_test_body',
            value: 'true',
          }],
        },
      },
    })
      .then((info) => {
        assert.equal(info.custom_test_body, true);
      }));
  });
});
