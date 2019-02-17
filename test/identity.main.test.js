const assert = require('chai').assert;
const {Oauth2Identity} = require('../');

describe('Oauth2Identity - main process', function() {
  this.timeout(10000);
  describe('_generateProviderId()', () => {
    it('Generates provider ID', () => {
      const result = Oauth2Identity._generateProviderId('https://auth.domain.com', 'http://clientId');
      assert.equal(result, 'https%3A%2F%2Fauth.domain.com/http%3A%2F%2FclientId');
    });
  });
  describe('_addProvider()', () => {
    it('creates Oauth2Identity.__providers', () => {
      const provider = {};
      Oauth2Identity._addProvider(provider);
      assert.lengthOf(Oauth2Identity.__providers, 1);
    });

    it('Adds new item to the list', () => {
      Oauth2Identity.__providers = [{}];
      const provider = {};
      Oauth2Identity._addProvider(provider);
      assert.lengthOf(Oauth2Identity.__providers, 2);
    });
  });

  describe('_getProvider()', () => {
    const authUri = 'https://auth.domain.com';
    const clientId = 'testClient';

    it('Returns undefined when no providers', () => {
      Oauth2Identity.__providers = undefined;
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.isUndefined(result);
    });

    it('Returns undefined provider not found', () => {
      Oauth2Identity.__providers = [{id: 'test'}];
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.isUndefined(result);
    });

    it('Returns the provider', () => {
      Oauth2Identity.__providers = [{
        id: 'https%3A%2F%2Fauth.domain.com/testClient'
      }];
      const result = Oauth2Identity._getProvider(authUri, clientId);
      assert.typeOf(result, 'object');
    });
  });

  describe('getOAuthConfig()', () => {
    it('Returns undefined when section is not defined', () => {
      return Oauth2Identity.getOAuthConfig()
      .then((result) => {
        assert.isUndefined(result);
      });
    });
  });
});
