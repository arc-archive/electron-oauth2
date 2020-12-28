const { assert } = require('chai');
const { IdentityProvider } = require('../');
const srv = require('./implicit-server.js');
const { aTimeout } = require('./TestHelpers');

describe('Implicit requests - main process', () => {
  const ID = 'test-instance-id';
  const clientId = 'test-client-id';
  const scopes = ['test1', 'test2'];
  const grantType = 'implicit';
  let serverPort;
  before(async () => {
    serverPort = await srv.create();
  });

  after(() => srv.shutdown());

  describe('launchWebAuthFlow()', () => {
    let instance = /** @type IdentityProvider */ (null);
    let params;
    before(() => {
      params = {
        grantType,
        clientId,
        redirectUri: `http://localhost:${serverPort}/auth/popup`,
        authorizationUri: `http://localhost:${serverPort}/auth`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('resolves to the token info', async () => {
      const tokenInfo = await instance.launchWebAuthFlow();
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, 'test-token');
      assert.equal(tokenInfo.tokenType, 'bearer');
      assert.equal(tokenInfo.expiresIn, 1800);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.deepEqual(tokenInfo.scope, ['test1', 'test2']);
    });

    it('clears the browser window after finish', async () => {
      await instance.launchWebAuthFlow();
      assert.isUndefined(instance.currentOAuthWindow);
      const { BrowserWindow } = require('electron');
      const wins = BrowserWindow.getAllWindows();
      assert.lengthOf(wins, 0);
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
      assert.isTrue(error.interactive);
      assert.typeOf(error.state, 'string');
    });

    it('supports the interactive state', async () => {
      const result = instance.launchWebAuthFlow({
        interactive: false,
      });
      await aTimeout(0);
      assert.isFalse(instance.currentOAuthWindow.isVisible());
      const tokenInfo = await result;
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, 'test-token');
      assert.equal(tokenInfo.tokenType, 'bearer');
      assert.equal(tokenInfo.expiresIn, 1800);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.deepEqual(tokenInfo.scope, ['test1', 'test2']);
    });

    it('results with error when interactive and no session', async () => {
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

    it('reports received from the server scopes', async () => {
      const tokenInfo = await instance.launchWebAuthFlow({
        customData: {
          auth: {
            parameters: [{
              name: 'custom_scope',
              value: 'true',
            }],
          },
        },
      });
      assert.typeOf(tokenInfo, 'object');
      assert.deepEqual(tokenInfo.scope, ['scope1', 'scope2']);
    });

    it('stores token in the cache store', async () => {
      const info = await instance.launchWebAuthFlow();
      const restored = await instance.restoreTokenInfo();
      assert.typeOf(restored, 'object');
      assert.equal(restored.accessToken, info.accessToken);
      assert.equal(restored.tokenType, info.tokenType);
      assert.equal(restored.expiresIn, info.expiresIn);
      assert.equal(restored.expiresAt, info.expiresAt);
      assert.deepEqual(restored.scope, info.scope);
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
  });
});
