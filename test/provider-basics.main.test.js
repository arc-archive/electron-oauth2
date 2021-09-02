/* eslint-disable no-empty-function */
const { assert } = require('chai');
const sinon = require('sinon');
const { IdentityProvider } = require('../index.js');
const {
  authorize,
  reportOAuthError,
  rejectFunction,
  resolveFunction,
  createErrorParams,
  computeExpires,
  processPopupRawData,
} = require('../lib/IdentityProvider.js');

describe('IdentityProvider class - main process', () => {
  const ID = 'test-instance-id';
  const baseSettings = {
    authorizationUri: 'http://test.com/auth',
    clientId: 'test client id',
    redirectUri: 'http://test.com/redirect',
    scopes: ['one', 'two'],
    includeGrantedScopes: true,
    loginHint: 'email@domain.com',
    interactive: false,
  };

  describe('constructor()', () => {
    it('sets the settings object', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      assert.deepEqual(auth.oauthConfig, baseSettings);
    });

    it('sets cacheKey', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      assert.equal(auth.cacheKey, `_oauth_cache_${ID}`);
    });
  });

  describe('checkConfig()', () => {
    // The check sanity is tested with the utils class tests,
    // this only checks whether the tests are called.
    it('throws when accessTokenUri is invalid', () => {
      // eslint-disable-next-line no-script-url
      const settings = { accessTokenUri: 'javascript://' };
      const auth = new IdentityProvider(ID, settings);
      assert.throws(() => {
        auth.checkConfig();
      });
    });
  });

  describe('[reportOAuthError]()', () => {
    it('rejects the main promise', async () => {
      const auth = new IdentityProvider(ID, {});
      auth[authorize] = () => {};
      const promise = auth.launchWebAuthFlow();
      auth[reportOAuthError]('test-message', 'test-code');
      let err;
      try {
        await promise;
      } catch (e) {
        err = e;
      }
      assert.ok(err, 'error is thrown');
      assert.equal(err.message, 'test-message', 'message');
      assert.equal(err.code, 'test-code', 'code is set');
      assert.typeOf(err.state, 'string', 'state is set');
      assert.isTrue(err.interactive, 'interactive is set');
    });

    it('does nothing when no reject function', async () => {
      const auth = new IdentityProvider(ID, {});
      auth[resolveFunction] = () => {};
      auth[reportOAuthError]('test-message', 'test-code');
      assert.ok(auth[resolveFunction]);
    });

    it('clears the [resolveFunction]', async () => {
      const auth = new IdentityProvider(ID, {});
      auth[resolveFunction] = () => {};
      auth[rejectFunction] = () => {};
      auth[reportOAuthError]('test-message', 'test-code');
      assert.isUndefined(auth[resolveFunction]);
    });

    it('clears the [rejectFunction]', async () => {
      const auth = new IdentityProvider(ID, {});
      auth[resolveFunction] = () => {};
      auth[rejectFunction] = () => {};
      auth[reportOAuthError]('test-message', 'test-code');
      assert.isUndefined(auth[rejectFunction]);
    });
  });

  describe('constructPopupUrl()', () => {
    const baseSettings = {
      authorizationUri: 'http://test.com/auth',
      clientId: 'test client id',
      redirectUri: 'http://test.com/redirect',
      scopes: ['one', 'two'],
      includeGrantedScopes: true,
      loginHint: 'email@domain.com',
      interactive: false,
    };
    const grantType = 'implicit';

    it('uses the authorization url', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isTrue(result.startsWith('http://test.com/auth?'));
    });

    it('sets the response_type property', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isTrue(result.includes('response_type=token&'));
    });

    it('sets the client_id property', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isTrue(result.includes('client_id=test+client+id&'));
    });

    it('sets the redirect_uri property', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isTrue(result.includes('redirect_uri=http%3A%2F%2Ftest.com%2Fredirect'));
    });

    it('sets the scopes property', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.notEqual(result.indexOf('scope=one+two'), -1);
    });

    it('sets state property', async () => {
      const cnf = { ...baseSettings, grantType, state: 'test state' };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.notEqual(result.indexOf('state=test+state'), -1);
    });

    it('sets Google OAuth 2 properties.', async () => {
      const cnf = { ...baseSettings, grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.notEqual(result.indexOf('include_granted_scopes=true'), -1);
      assert.notEqual(result.indexOf('prompt=none'), -1);
      assert.notEqual(result.indexOf('login_hint=email%40domain.com'), -1);
    });

    it('skips the redirect_uri if not set', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.redirectUri = undefined;
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('redirect_uri='), -1);
    });

    it('skips the scope if not set', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.scopes = undefined;
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('scope='), -1);
    });

    it('skips the include_granted_scopes if not set', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.includeGrantedScopes = undefined;
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('include_granted_scopes='), -1);
    });

    it('skips the prompt if not set', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.interactive = undefined;
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('prompt='), -1);
    });

    it('skips the login_hint if not set', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.loginHint = undefined;
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('login_hint='), -1);
    });

    it('do not inserts "?" when auth url already contains it', async () => {
      const cnf = { ...baseSettings, grantType };
      cnf.authorizationUri = 'http://test.com/auth?custom=value';
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.equal(result.indexOf('http://test.com/auth?custom=value&response_type'), 0);
    });

    it('adds code_challenge for PKCE extension', async () => {
      const cnf = { ...baseSettings, grantType: 'authorization_code', pkce: true };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      const url = new URL(result);
      const challenge = url.searchParams.get('code_challenge');
      assert.typeOf(challenge, 'string', 'the challenge is set');
      const method = url.searchParams.get('code_challenge_method');
      assert.equal(method, 'S256', 'the method is set');
    });

    it('sets codeVerifier', async () => {
      const cnf = { ...baseSettings, grantType: 'authorization_code', pkce: true };
      const auth = new IdentityProvider(ID, cnf);
      await auth.constructPopupUrl();
      const verifier = auth.codeVerifier;
      assert.typeOf(verifier, 'string', 'the verifier is set');
      assert.isAbove(verifier.length, 42); // min length 43 characters
      assert.isBelow(verifier.length, 129); // max length 128 characters
    });

    it('sets the client_id', async () => {
      const cnf = { ...baseSettings, clientSecret: 'secret', grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isTrue(result.includes('client_id=test+client+id'));
    });

    it('does not set client_secret', async () => {
      const cnf = { ...baseSettings, clientSecret: 'secret', grantType };
      const auth = new IdentityProvider(ID, cnf);
      const result = await auth.constructPopupUrl();
      assert.isFalse(result.includes('client_secret=secret'));
    });
  });

  describe('storeToken()', () => {
    let instance = /** @type IdentityProvider */ (null);
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      content = {
        accessToken: 'test-token',
      };
    });

    it('Stores data in the store', () => {
      instance.storeToken(content);
      const data = instance.tokenStore.get(instance.cacheKey);
      assert.deepEqual(data, content);
    });

    it('Returns a promise', () => {
      const result = instance.storeToken(content);
      assert.typeOf(result, 'promise');
    });
  });

  describe('restoreTokenInfo()', () => {
    let instance = /** @type IdentityProvider */ (null);
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      instance.tokenStore.clear();
      content = {
        accessToken: 'test-token',
      };
    });

    function storeData() {
      instance.storeToken(content);
    }

    it('Returns a promise', () => {
      const result = instance.restoreTokenInfo();
      assert.typeOf(result, 'promise');
    });

    it('Results to undefined when no data', () => instance.restoreTokenInfo()
      .then((result) => {
        assert.isUndefined(result);
      }));

    it('Results to stored data', () => {
      storeData();
      return instance.restoreTokenInfo()
        .then((result) => {
          assert.deepEqual(result, content);
        });
    });
  });

  describe('clearCache()', () => {
    let instance = /** @type IdentityProvider */ (null);
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      content = {
        accessToken: 'test-token',
        tokenType: 'code',
        expiresIn: 3600,
        expiresAt: 3600,
        expiresAssumed: false,
        state: '1234',
      };
      instance.storeToken(content);
    });

    it('removes stored data', async () => {
      instance.clearCache();
      const result = await instance.restoreTokenInfo();
      assert.isUndefined(result);
    });
  });

  describe('[createErrorParams]()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
    });

    let client = /** @type IdentityProvider */ (null);
    beforeEach(() => {
      client = new IdentityProvider(ID, baseSettings);
    });

    it('returns passed code', () => {
      const result = client[createErrorParams]('my-code');
      assert.equal(result[1], 'my-code');
    });

    it('returns the default message', () => {
      const result = client[createErrorParams]('my-code');
      assert.equal(result[0], 'Unknown error');
    });

    it('returns passed message', () => {
      const result = client[createErrorParams]('my-code', 'a message');
      assert.equal(result[0], 'a message');
    });

    [
      ['interaction_required', 'The request requires user interaction.'],
      ['invalid_request', 'The request is missing a required parameter.'],
      ['invalid_client', 'Client authentication failed.'],
      ['invalid_grant', 'The provided authorization grant or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.'],
      ['unauthorized_client', 'The authenticated client is not authorized to use this authorization grant type.'],
      ['unsupported_grant_type', 'The authorization grant type is not supported by the authorization server.'],
      ['invalid_scope', 'The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.'],
    ].forEach(([code, message]) => {
      it(`returns message for the ${code} code`, () => {
        const result = client[createErrorParams](code);
        assert.equal(result[0], message);
      });
    });
  });

  describe('[computeExpires]()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
    });

    const baseToken = Object.freeze({
      accessToken: 'abc',
      tokenType: 'bearer',
      expiresIn: 12,
      expiresAt: undefined,
      expiresAssumed: false,
      state: '123',
    });

    let client = /** @type IdentityProvider */ (null);
    beforeEach(() => {
      client = new IdentityProvider(ID, baseSettings);
    });

    it('returns a copy', () => {
      const result = client[computeExpires](baseToken);
      assert.isFalse(result === baseToken);
    });

    it('sets expiresAt', () => {
      const result = client[computeExpires](baseToken);
      assert.typeOf(result.expiresAt, 'number');
    });

    it('adds default expiresIn', () => {
      const info = { ...baseToken };
      delete info.expiresIn;
      const result = client[computeExpires](info);
      assert.equal(result.expiresIn, 3600);
    });

    it('fixes NaN expiresIn', () => {
      const info = { ...baseToken };
      info.expiresIn = Number('nan');
      const result = client[computeExpires](info);
      assert.equal(result.expiresIn, 3600);
    });
  });

  describe('[processPopupRawData]()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
    });

    it('calls processTokenResponse for hash part', () => {
      const client = new IdentityProvider(ID, baseSettings);
      client[rejectFunction] = () => {};
      const spy = sinon.spy(client, 'processTokenResponse');
      client[processPopupRawData]('https://api.com#access_token=b');
      assert.isTrue(spy.called);
    });

    it('calls processTokenResponse for search part', () => {
      const client = new IdentityProvider(ID, baseSettings);
      client[rejectFunction] = () => {};
      const spy = sinon.spy(client, 'processTokenResponse');
      client[processPopupRawData]('https://api.com?code=b');
      assert.isTrue(spy.called);
    });

    it('ignores when no parameters', () => {
      const client = new IdentityProvider(ID, baseSettings);
      client[rejectFunction] = () => {};
      const spy = sinon.spy(client, 'processTokenResponse');
      client[processPopupRawData]('');
      assert.isFalse(spy.called);
    });
  });
});
