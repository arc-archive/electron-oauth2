// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const { assert } = require('chai');
const { IdentityProvider } = require('../');
const srv = require('./password-server');

describe('Password requests - main process', () => {
  const ID = 'test-instance-id-password-request';
  const clientId = 'test-client-id-password-request';
  const scopes = ['password1', 'password1'];
  const grantType = 'password';
  const username = 'test-user';
  const password = 'test-pwd';
  const expectedToken = 'test-password-token';
  const expectedTokenType = 'test-password-type';
  const expectedRefreshToken = 'password-refresh-token';
  let serverPort;
  before(async () => {
    serverPort = await srv.create();
  });

  after(() => srv.shutdown());

  describe('launchWebAuthFlow()', () => {
    let instance;
    let params;
    before(() => {
      params = {
        grantType,
        clientId,
        accessTokenUri: `http://localhost:${serverPort}/token`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('resolves to the token info', async () => {
      const tokenInfo = await instance.launchWebAuthFlow({
        username,
        password,
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
          customData: {
            token: {
              body: [{
                name: 'custom_fail_request',
                value: 'true',
              }],
            },
          },
        });
      } catch (cause) {
        error = cause;
      }
      assert.equal(error.code, 'request_error');
    });

    it('stores the token in cache store', async () => {
      const info = await instance.launchWebAuthFlow({
        username,
        password,
      });
      const restored = await instance.restoreTokenInfo();
      assert.typeOf(restored, 'object');
      assert.equal(restored.accessToken, info.accessToken);
      assert.equal(restored.access_token, info.access_token);
      assert.equal(restored.tokenType, info.tokenType);
      assert.equal(restored.token_type, info.token_type);
      assert.equal(restored.expiresIn, info.expiresIn);
      assert.equal(restored.expires_in, info.expires_in);
      assert.equal(restored.expiresAt, info.expiresAt);
    });

    it('handles the application/x-www-form-urlencoded response data', async () => {
      const info = await instance.launchWebAuthFlow({
        username,
        password,
        customData: {
          token: {
            headers: [{
              name: 'accept',
              value: 'application/x-www-form-urlencoded',
            }],
          },
        },
      });
      assert.typeOf(info, 'object');
      assert.equal(info.accessToken, expectedToken);
      assert.equal(info.tokenType, expectedTokenType);
      assert.equal(info.expiresIn, 900);
      assert.typeOf(info.expiresAt, 'number');
      assert.equal(info.refreshToken, expectedRefreshToken);
    });

    it('sends custom query parameters', async () => {
      const info = await instance.launchWebAuthFlow({
        username,
        password,
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
      assert.equal(info.customTestUrl, true);
    });

    it('sends custom headers', async () => {
      const info = await instance.launchWebAuthFlow({
        username,
        password,
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
      assert.equal(info.customTestHeaders, true);
    });

    it('sends custom body parameters', async () => {
      const info = await instance.launchWebAuthFlow({
        username,
        password,
        customData: {
          token: {
            body: [{
              name: 'custom_test_body',
              value: 'true',
            }],
          },
        },
      });
      assert.equal(info.customTestBody, true);
    });
  });
});
