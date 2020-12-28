/* eslint-disable no-script-url */
// eslint-disable-next-line import/no-unresolved
const { assert } = require('chai');
const { checkUrl, sanityCheck, randomString, camel } = require('../lib/Utils');


describe('Utils', () => {
  describe('checkUrl()', () => {
    it('throws when no argument', () => {
      assert.throws(() => {
        checkUrl(undefined);
      }, 'the value is missing');
    });

    it('throws when argument is not a string', () => {
      assert.throws(() => {
        // @ts-ignore
        checkUrl(100);
      }, 'the value is not a string');
    });

    it('throws when argument does not start with http or https', () => {
      assert.throws(() => {
        checkUrl('javascript:http://%0Aalert(document.domain);//');
      }, 'the value has invalid scheme');
    });

    it('passes for valid http: scheme', () => {
      checkUrl('http://api.domain.com');
    });

    it('passes for valid https: scheme', () => {
      checkUrl('https://api.domain.com');
    });
  });

  describe('sanityCheck()', () => {
    it('throws when accessTokenUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          accessTokenUri: 'javascript://',
        });
      });
    });

    it('implicit: throws when accessTokenUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'https://domain.com',
          accessTokenUri: 'javascript://',
          grantType: 'implicit',
        });
      });
    });

    it('implicit: throws when authorizationUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'javascript://',
          grantType: 'implicit',
        });
      });
    });

    it('implicit: throws when redirectUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'javascript://',
          grantType: 'implicit',
        });
      });
    });

    it('authorization_code: throws when accessTokenUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'https://domain.com',
          accessTokenUri: 'javascript://',
          grantType: 'authorization_code',
        });
      });
    });

    it('authorization_code: throws when authorizationUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'javascript://',
          grantType: 'authorization_code',
        });
      });
    });

    it('authorization_code: throws when redirectUri is invalid', () => {
      assert.throws(() => {
        sanityCheck({
          authorizationUri: 'javascript://',
          grantType: 'authorization_code',
        });
      });
    });
  });

  describe('randomString()', () => {
    it('generates a random string', () => {
      const result = randomString();
      assert.typeOf(result, 'string');
    });
  });

  describe('camel()', () => {
    it('returns undefined if not changed', () => {
      const result = camel('noop');
      assert.isUndefined(result);
    });

    it('returns camel cased with "-"', () => {
      const result = camel('property-name-item');
      assert.equal(result, 'propertyNameItem');
    });

    it('returns camel cased with "_"', () => {
      const result = camel('property_name_item');
      assert.equal(result, 'propertyNameItem');
    });
  });
});
