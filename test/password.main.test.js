// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const { assert } = require('chai');
const { IdentityProvider } = require('../');
const srv = require('./password-server');

describe('Password requests - main process', () => {
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
        token_uri: `http://localhost:${serverPort}/token`,
        scopes,
      };
      instance = new IdentityProvider(ID, params);
    });

    it('Returns promise resolved to token', () => instance.launchWebAuthFlow({
      username,
      password,
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
      }));

    it('Handles errors', (done) => {
      instance.launchWebAuthFlow({
        username,
        password,
        customData: {
          token: {
            body: [{
              name: 'custom_fail_request',
              value: 'true',
            }],
          },
        },
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

    it('Store token in cache store', () => {
      let info;
      return instance.launchWebAuthFlow({
        username,
        password,
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

    it('Handles application/x-www-form-urlencoded response data', () => instance.launchWebAuthFlow({
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
      }));

    it('Sends custom query parameetrs', () => instance.launchWebAuthFlow({
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
    })
      .then((info) => {
        assert.equal(info.custom_test_url, true);
      }));

    it('Sends custom headers', () => instance.launchWebAuthFlow({
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
    })
      .then((info) => {
        assert.typeOf(info, 'object');
        assert.equal(info.custom_test_headers, true);
      }));

    it('Sends custom body parameetrs', () => instance.launchWebAuthFlow({
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
    })
      .then((info) => {
        assert.equal(info.custom_test_body, true);
      }));
  });
});
