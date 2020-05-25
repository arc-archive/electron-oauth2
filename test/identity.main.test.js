const { assert } = require('chai');
const { Oauth2Identity, IdentityProvider } = require('../');

describe('Oauth2Identity - main process', () => {
  describe('_generateProviderId()', () => {
    it('Generates provider ID', () => {
      const result = Oauth2Identity._generateProviderId('https://auth.domain.com', 'http://clientId');
      assert.equal(result, 'https%3A%2F%2Fauth.domain.com/http%3A%2F%2FclientId');
    });
  });

  describe('_addProvider()', () => {
    it('adds a provider to the list', () => {
      const provider = new IdentityProvider('a/b', {});
      Oauth2Identity._addProvider(provider);
      const result = Oauth2Identity._getProvider('a', 'b');
      assert.ok(result);
    });
  });

  describe('_getProvider()', () => {
    const authUri = 'https://auth.domain.com';
    const clientId = 'testClient';

    it('Returns undefined when no providers', () => {
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.isUndefined(result);
    });

    it('returns undefined provider not found', () => {
      const provider = new IdentityProvider('a/b', {});
      Oauth2Identity._addProvider(provider);
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.isUndefined(result);
    });

    it('Returns the provider', () => {
      const id = Oauth2Identity._generateProviderId(authUri, clientId);
      const provider = new IdentityProvider(id, {});
      Oauth2Identity._addProvider(provider);
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.typeOf(result, 'object');
    });
  });

  describe('getOAuthConfig()', () => {
    it('Returns undefined when oauth config section is not defined', async () => {
      const result = await Oauth2Identity.getOAuthConfig();
      assert.isUndefined(result);
    });
  });
});
