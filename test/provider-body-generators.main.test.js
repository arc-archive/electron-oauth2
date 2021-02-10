const { assert } = require('chai');
const { IdentityProvider } = require('../');

describe('Request body generators - main process', () => {
  const ID = 'test-instance-id';

  describe('getCodeRequestBody()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
      redirectUri: 'https://auth.api.com/oauth',
      clientSecret: 'client secret',
    });
    const code = 'my code';

    it('has the grant_type', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCodeRequestBody(code);
      assert.include(result, 'grant_type=authorization_code&');
    });

    it('has the client_id', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCodeRequestBody(code);
      assert.include(result, 'client_id=test+client+id&');
    });

    it('has the redirect_uri', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCodeRequestBody(code);
      assert.include(result, 'redirect_uri=https%3A%2F%2Fauth.api.com%2Foauth&');
    });

    it('has the code', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCodeRequestBody(code);
      assert.include(result, 'code=my+code&');
    });

    it('has the client_secret', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCodeRequestBody(code);
      assert.include(result, 'client_secret=client+secret');
    });

    it('ignores the redirect_uri when not set', () => {
      const config = { ...baseSettings };
      delete config.redirectUri;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCodeRequestBody(code);
      assert.isFalse(result.includes('redirect_uri'));
    });

    it('sets empty client_secret when not set', () => {
      const config = { ...baseSettings };
      delete config.clientSecret;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCodeRequestBody(code);
      assert.isTrue(result.endsWith('client_secret='));
    });
  });

  describe('getClientCredentialsBody()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
      scopes: ['scope1', 'scope2'],
      clientSecret: 'client secret',
      deliveryMethod: undefined,
    });

    it('has the grant_type', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsBody();
      assert.include(result, 'grant_type=client_credentials&');
    });

    it('has the client_id', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsBody();
      assert.include(result, 'client_id=test+client+id&');
    });

    it('has the client_secret', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsBody();
      assert.include(result, 'client_secret=client+secret');
    });

    it('has the scope', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsBody();
      assert.include(result, 'scope=scope1+scope2');
    });

    it('ignores the client_secret when not set', () => {
      const config = { ...baseSettings };
      delete config.clientSecret;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getClientCredentialsBody();
      assert.isFalse(result.includes('client_secret'));
    });

    it('ignores the scope when not set', () => {
      const config = { ...baseSettings };
      delete config.scopes;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getClientCredentialsBody();
      assert.isFalse(result.includes('scope='));
    });

    it('ignores the client_id when header location', () => {
      const config = { ...baseSettings };
      config.deliveryMethod = 'header';
      const auth = new IdentityProvider(ID, config);
      const result = auth.getClientCredentialsBody();
      assert.notInclude(result, 'client_id=');
    });

    it('ignores the client_secret when header location', () => {
      const config = { ...baseSettings };
      config.deliveryMethod = 'header';
      const auth = new IdentityProvider(ID, config);
      const result = auth.getClientCredentialsBody();
      assert.notInclude(result, 'client_secret=');
    });
  });

  describe('getClientCredentialsHeader()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
      clientSecret: 'client secret',
    });

    it('encodes the parameters', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsHeader(baseSettings);
      assert.equal(result, 'Basic dGVzdCBjbGllbnQgaWQ6Y2xpZW50IHNlY3JldA==');
    });

    it('uses the default clientId', () => {
      const init = { ...baseSettings };
      delete init.clientId;
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsHeader(init);
      assert.equal(result, 'Basic OmNsaWVudCBzZWNyZXQ=');
    });

    it('uses the default clientSecret', () => {
      const init = { ...baseSettings };
      delete init.clientSecret;
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getClientCredentialsHeader(init);
      assert.equal(result, 'Basic dGVzdCBjbGllbnQgaWQ6');
    });
  });

  describe('getPasswordBody()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
      scopes: ['scope1', 'scope2'],
      username: 'uname',
      password: 'passwd',
      clientSecret: 'test-secret',
    });

    it('has the grant_type', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'grant_type=password&');
    });

    it('has the username', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'username=uname');
    });

    it('has the password', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'password=passwd');
    });

    it('has the client_id', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'client_id=test+client+id&');
    });

    it('has the scope', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'scope=scope1+scope2');
    });

    it('has the client_secret', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getPasswordBody();
      assert.include(result, 'client_secret=test-secret');
    });

    it('ignores the client_id when not set', () => {
      const config = { ...baseSettings };
      delete config.clientId;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getPasswordBody();
      assert.isFalse(result.includes('client_id'));
    });

    it('ignores the scope when not set', () => {
      const config = { ...baseSettings };
      delete config.scopes;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getPasswordBody();
      assert.isFalse(result.includes('scope='));
    });

    it('ignores the client_secret when not set', () => {
      const config = { ...baseSettings };
      delete config.clientSecret;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getPasswordBody();
      assert.isFalse(result.includes('client_secret'));
    });
  });

  describe('getCustomGrantBody()', () => {
    const baseSettings = Object.freeze({
      clientId: 'test client id',
      scopes: ['scope1', 'scope2'],
      username: 'uname',
      password: 'passwd',
      clientSecret: 'client secret',
      redirectUri: 'https://auth.api.com/oauth',
      grantType: 'custom',
    });

    it('has the grant_type', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'grant_type=custom&');
    });

    it('has the username', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'username=uname');
    });

    it('ignores the username when not set', () => {
      const config = { ...baseSettings };
      delete config.username;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('username'));
    });

    it('has the password', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'password=passwd');
    });

    it('ignores the password when not set', () => {
      const config = { ...baseSettings };
      delete config.password;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('password'));
    });

    it('has the client_id', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'client_id=test+client+id&');
    });

    it('ignores the client_id when not set', () => {
      const config = { ...baseSettings };
      delete config.clientId;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('client_id'));
    });

    it('has the scope', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'scope=scope1+scope2');
    });

    it('ignores the scope when not set', () => {
      const config = { ...baseSettings };
      delete config.scopes;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('scope='));
    });

    it('has the redirect_uri', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'redirect_uri=https%3A%2F%2Fauth.api.com%2Foauth&');
    });

    it('ignores the redirect_uri when not set', () => {
      const config = { ...baseSettings };
      delete config.redirectUri;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('redirect_uri'));
    });

    it('has the client_secret', () => {
      const auth = new IdentityProvider(ID, baseSettings);
      const result = auth.getCustomGrantBody();
      assert.include(result, 'client_secret=client+secret');
    });

    it('ignores the client_secret when not set', () => {
      const config = { ...baseSettings };
      delete config.clientSecret;
      const auth = new IdentityProvider(ID, config);
      const result = auth.getCustomGrantBody();
      assert.isFalse(result.includes('client_secret'));
    });
  });
});
