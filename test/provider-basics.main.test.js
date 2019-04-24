const assert = require('chai').assert;
const {IdentityProvider} = require('../');

describe('IdentityProvider class - main process', function() {
  const ID = 'test-instance-id';
  const baseSettings = {
    authorizationUri: 'http://test.com/auth',
    clientId: 'test client id',
    redirectUri: 'http://test.com/redirect',
    scopes: ['one', 'two'],
    includeGrantedScopes: true,
    loginHint: 'email@domain.com',
    interactive: false
  };
  describe('_constructPopupUrl()', () => {
    let instance;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
    });
    const defaultType = 'token';

    it('Sets authorization url', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.equal(result.indexOf('http://test.com/auth?'), 0);
    });

    it('Sets response_type property', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('response_type=token&'), -1);
    });

    it('Sets client_id property', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('client_id=test%20client%20id&'), -1);
    });

    it('Sets redirect_uri property', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('redirect_uri=http%3A%2F%2Ftest.com%2Fredirect'), -1);
    });

    it('Sets scopes property', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('scope=one%20two'), -1);
    });

    it('Sets state property', () => {
      instance._state = 'test state';
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('state=test%20state'), -1);
    });

    it('Sets Google Oauth properties.', () => {
      let result = instance._constructPopupUrl(baseSettings, defaultType);
      assert.notEqual(result.indexOf('include_granted_scopes=true'), -1);
      assert.notEqual(result.indexOf('prompt=none'), -1);
      assert.notEqual(result.indexOf('login_hint=email%40domain.com'), -1);
    });

    it('Skips redirect_uri if not set', () => {
      let settings = Object.assign({}, baseSettings);
      settings.redirectUri = undefined;
      let result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('redirect_uri='), -1);
    });

    it('Skips scope if not set', () => {
      const settings = Object.assign({}, baseSettings);
      settings.scopes = undefined;
      instance.oauthConfig.scopes = undefined;
      const result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('scope=&'), -1);
    });

    it('Skips include_granted_scopes if not set', () => {
      let settings = Object.assign({}, baseSettings);
      settings.includeGrantedScopes = undefined;
      let result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('include_granted_scopes='), -1);
    });

    it('Skips prompt if not set', () => {
      let settings = Object.assign({}, baseSettings);
      settings.interactive = undefined;
      let result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('prompt='), -1);
    });

    it('Skips login_hint if not set', () => {
      let settings = Object.assign({}, baseSettings);
      settings.loginHint = undefined;
      let result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('login_hint='), -1);
    });

    it('Do not inserts "?" when auth url already contains it', () => {
      let settings = Object.assign({}, baseSettings);
      settings.authorizationUri = 'http://test.com/auth?custom=value';
      let result = instance._constructPopupUrl(settings, defaultType);
      assert.equal(result.indexOf('http://test.com/auth?custom=value&response_type'), 0);
    });
  });

  describe('randomString()', () => {
    let instance;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
    });

    it('Generates string of 6', () => {
      const result = instance.randomString();
      assert.typeOf(result, 'string');
      assert.lengthOf(result, 6);
    });
  });

  describe('_computeScope()', () => {
    let instance;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
    });

    it('Returns empty stirng for no argument', () => {
      const result = instance._computeScope();
      assert.strictEqual(result, '');
    });

    it('Returns value for single scope', () => {
      const result = instance._computeScope(['one']);
      assert.strictEqual(result, 'one');
    });

    it('Returns value for multiple scopes', () => {
      const result = instance._computeScope(['one', 'two']);
      assert.strictEqual(result, 'one%20two');
    });
  });

  describe('_camel()', () => {
    let instance;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
    });
    it('Renturns undefined if not changed', () => {
      let result = instance._camel('noop');
      assert.isUndefined(result);
    });
    it('Renturns camel cased wirh "-"', () => {
      let result = instance._camel('property-name-item');
      assert.equal(result, 'propertyNameItem');
    });
    it('Renturns camel cased wirh "_"', () => {
      let result = instance._camel('property_name_item');
      assert.equal(result, 'propertyNameItem');
    });
  });

  describe('Custom OAuth data', () => {
    let instance;
    let params = {
      type: 'custom_grant',
      clientId: 'test',
      clientSecret: 'test',
      authorizationUri: 'https://auth.domain.com',
      username: 'user-test',
      password: 'pass-test',
      customData: {
        auth: {
          parameters: [{
            name: 'aqp1',
            value: 'aqpv1'
          }]
        },
        token: {
          parameters: [{
            name: 'tqp1',
            value: 'tqpv1'
          }],
          headers: [{
            name: 'th1',
            value: 'thv1'
          }],
          body: [{
            name: 'tb1',
            value: 'tbv1'
          }]
        }
      }
    };
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      instance._settting = params;
      instance._state = 'test-state';
    });

    describe('_applyCustomSettingsQuery()', () => {
      it('returns a string', () => {
        let result = instance._applyCustomSettingsQuery('', params.customData.auth);
        assert.typeOf(result, 'string');
      });
      it('returns the same string when no settings', () => {
        let result = instance._applyCustomSettingsQuery('', {});
        assert.equal(result, '');
      });
      it('returns params in query string.', () => {
        let result = instance._applyCustomSettingsQuery('', params.customData.auth);
        assert.equal(result, '?aqp1=aqpv1');
      });
    });

    describe('_constructPopupUrl()', () => {
      it('Applies params to the url for implicit type', () => {
        let result = instance._constructPopupUrl(params, 'token');
        let compare = 'https://auth.domain.com?response_type=token&client_id=';
        compare += 'test&&state=test-state&aqp1=aqpv1';
        assert.equal(result, compare);
      });
      it('Applies params to the url for authorization_code type', () => {
        let result = instance._constructPopupUrl(params, 'code');
        let compare = 'https://auth.domain.com?response_type=code&client_id=';
        compare += 'test&&state=test-state&aqp1=aqpv1';
        assert.equal(result, compare);
      });
    });

    describe('_applyCustomSettingsBody()', () => {
      it('returns a string', () => {
        let result = instance._applyCustomSettingsBody('', params.customData);
        assert.typeOf(result, 'string');
      });
      it('returns the same string when no settings', () => {
        let result = instance._applyCustomSettingsBody('', {});
        assert.equal(result, '');
      });
      it('returns params in query string.', () => {
        let result = instance._applyCustomSettingsBody('', params.customData);
        assert.equal(result, '&tb1=tbv1');
      });
    });
  });

  describe('storeToken()', () => {
    let instance;
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      content = {
        accessToken: 'test-token'
      };
    });

    it('Stores data in the store', () => {
      instance.storeToken(content);
      const data = instance.tokentStore.get(instance.cacheKey);
      assert.deepEqual(data, content);
    });

    it('Returns a promise', () => {
      const result = instance.storeToken(content);
      assert.typeOf(result, 'promise');
    });
  });

  describe('restoreTokenInfo()', () => {
    let instance;
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      instance.tokentStore.clear();
      content = {
        accessToken: 'test-token'
      };
    });

    function storeData() {
      instance.storeToken(content);
    }

    it('Returns a promise', () => {
      const result = instance.restoreTokenInfo();
      assert.typeOf(result, 'promise');
    });

    it('Results to undefined when no data', () => {
      return instance.restoreTokenInfo()
      .then((result) => {
        assert.isUndefined(result);
      });
    });

    it('Results to stored data', () => {
      storeData();
      return instance.restoreTokenInfo()
      .then((result) => {
        assert.deepEqual(result, content);
      });
    });
  });

  describe('clearCache()', () => {
    let instance;
    let content;
    beforeEach(() => {
      instance = new IdentityProvider(ID, baseSettings);
      content = {
        accessToken: 'test-token'
      };
      instance.storeToken(content);
    });

    it('Removes stored data', () => {
      instance.clearCache();
      return instance.restoreTokenInfo()
      .then((result) => {
        assert.isUndefined(result);
      });
    });

    it('Clears tokenInfo', () => {
      instance.tokenInfo = 'test';
      instance.clearCache();
      assert.isUndefined(instance.tokenInfo);
    });
  });
});
