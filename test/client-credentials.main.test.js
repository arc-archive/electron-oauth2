const { assert } = require('chai');
const { IdentityProvider } = require('../');
const srv = require('./client-credentials-server');

/** @typedef {import('@advanced-rest-client/arc-types').Authorization.OAuth2Authorization} OAuth2Authorization */

describe('Client credentials requests - main process', () => {
  const ID = 'test-instance-id-cc-request';
  const clientId = 'test-client-id-cc-request';
  const clientSecret = 'test-client-secret-cc-request';
  const scopes = ['s1', 's2'];
  const grantType = 'client_credentials';
  const expectedToken = 'test-cc-token';
  const expectedTokenType = 'test-cc-type';
  const expectedRefreshToken = 'cc-refresh-token';
  let serverPort;
  before(async () => {
    serverPort = await srv.create();
  });

  after(() => srv.shutdown());

  describe('launchWebAuthFlow()', () => {
    let instance = /** @type IdentityProvider */ (null);
    let params = /** @type OAuth2Authorization */ (null);
    before(() => {
      params = {
        grantType,
        clientId,
        clientSecret,
        accessTokenUri: `http://localhost:${serverPort}/token`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('resolves to the token info via body transport (default)', async () => {
      const tokenInfo = await instance.launchWebAuthFlow();
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, expectedToken);
      assert.equal(tokenInfo.tokenType, expectedTokenType);
      assert.equal(tokenInfo.expiresIn, 900);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
    });

    it('resolves to the token info via the auth header transport', async () => {
      const tokenInfo = await instance.launchWebAuthFlow({
        deliveryMethod: 'header',
        deliveryName: 'authorization',
      });
      assert.typeOf(tokenInfo, 'object');
      assert.equal(tokenInfo.accessToken, expectedToken);
      assert.equal(tokenInfo.tokenType, expectedTokenType);
      assert.equal(tokenInfo.expiresIn, 900);
      assert.typeOf(tokenInfo.expiresAt, 'number');
      assert.equal(tokenInfo.refreshToken, expectedRefreshToken);
    });

    it('handles errors', async () => {
      let error;
      try {
        await instance.launchWebAuthFlow({
          deliveryMethod: 'header',
          deliveryName: 'invalid',
        });
      } catch (cause) {
        error = cause;
      }
      assert.equal(error.code, 'request_error');
    });

    it('resolves to the token info via body transport (default)', async () => {
      const info = await instance.launchWebAuthFlow();
      const restored = await instance.restoreTokenInfo();
      assert.typeOf(restored, 'object');
      assert.equal(restored.accessToken, info.accessToken);
      assert.equal(restored.tokenType, info.tokenType);
      assert.equal(restored.expiresIn, info.expiresIn);
      assert.equal(restored.expiresAt, info.expiresAt);
    });
  });
});
