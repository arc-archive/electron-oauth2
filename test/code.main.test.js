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
    let instance = /** @type IdentityProvider */ (null);
    let params;
    before(() => {
      params = {
        responseType,
        clientId,
        clientSecret,
        redirectUri: `http://localhost:${serverPort}/auth/popup`,
        authorizationUri: `http://localhost:${serverPort}/auth`,
        accessTokenUri: `http://localhost:${serverPort}/token`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', async () => {
      const tokenInfo = await instance.launchWebAuthFlow();
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, expectedToken);
      assert.equal(tokenInfo.tokenType, expectedTokenType);
      assert.equal(tokenInfo.expiresIn, 2700);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
    });

    it('handles errors', async () => {
      let error;
      try {
        await instance.launchWebAuthFlow({
          customData: {
            auth: {
              parameters: [{
                name: 'custom_report_error',
                value: 'true',
              }],
            },
          },
        });
      } catch (cause) {
        error = cause;
      }
      assert.equal(error.code, 'test-error');
      assert.equal(error.message, 'test-error-message');
      assert.isUndefined(error.interactive);
      assert.typeOf(error.state, 'string');
    });

    it('supports interactive state', async () => {
      const result = instance.launchWebAuthFlow({
        interactive: false,
      });
      assert.isFalse(instance.currentOAuthWindow.isVisible());
      const tokenInfo = await result;
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, 'test-code-token');
    });

    it('result with error when interactive and no session', async () => {
      let error;
      try {
        await instance.launchWebAuthFlow({
          interactive: false,
          customData: {
            auth: {
              parameters: [{
                name: 'custom_no_session',
                value: 'true',
              }],
            },
          },
        });
      } catch (cause) {
        error = cause;
      }
      assert.equal(error.code, 'auth_error');
      assert.equal(error.message, 'No response from the server.');
      assert.typeOf(error.state, 'string');
    });

    it('Store token in cache store', async () => {
      const info = await instance.launchWebAuthFlow();
      const restored = await instance.restoreTokenInfo();
      assert.typeOf(restored, 'object');
      assert.equal(restored.accessToken, info.accessToken);
      assert.equal(restored.tokenType, info.tokenType);
      assert.equal(restored.expiresIn, info.expiresIn);
      assert.equal(restored.expiresAt, info.expiresAt);
    });

    it('waits until page is redirected', async () => {
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

    it('reports an error when window is closed without response', (done) => {
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

    it('handles application/x-www-form-urlencoded response data', async () => {
      const tokenInfo = await instance.launchWebAuthFlow({
        customData: {
          token: {
            headers: [{
              name: 'accept',
              value: 'application/x-www-form-urlencoded',
            }],
          },
        },
      });
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, expectedToken);
      assert.equal(tokenInfo.tokenType, expectedTokenType);
      assert.equal(tokenInfo.expiresIn, 2700);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
    });

    it('sends custom query parameters', async () => {
      const info = await instance.launchWebAuthFlow({
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
      });
      // @ts-ignore
      assert.equal(info.custom_test_url, true);
    });

    it('Sends custom headers', async () => {
      const info = await instance.launchWebAuthFlow({
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
      });
      assert.typeOf(info, 'object');
      // @ts-ignore
      assert.equal(info.custom_test_headers, true);
    });

    it('Sends custom body parameters', async () => {
      const info = await instance.launchWebAuthFlow({
        customData: {
          token: {
            body: [{
              name: 'custom_test_body',
              value: 'true',
            }],
          },
        },
      });
      // @ts-ignore
      assert.equal(info.custom_test_body, true);
    });
  });
});
