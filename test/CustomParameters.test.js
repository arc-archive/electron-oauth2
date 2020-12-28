const { assert } = require('chai');
const { applyCustomSettingsQuery, applyCustomSettingsBody, applyCustomSettingsHeaders } = require('../lib/CustomParameters.js');

describe('CustomParameters', () => {
  describe('applyCustomSettingsQuery()', () => {
    const params = {
      parameters: [{
        name: 'aqp1',
        value: 'aqQv1',
      }],
    };

    it('returns unchanged URL when no settings', () => {
      const value = 'https://api.domain.com/?a=b';
      const instance = new URL(value);
      applyCustomSettingsQuery(instance, {});
      assert.equal(instance.toString(), value);
    });

    it('returns params in query string.', () => {
      const value = 'https://api.domain.com/?a=b';
      const instance = new URL(value);
      applyCustomSettingsQuery(instance, params);
      assert.equal(instance.toString(), `${value}&aqp1=aqQv1`);
    });
  });

  describe('applyCustomSettingsBody()', () => {
    const customData = {
      auth: {
        parameters: [{
          name: 'aqp1',
          value: 'aqQv1',
        }],
      },
      token: {
        parameters: [{
          name: 'tqp1',
          value: 'tqQv1',
        }],
        headers: [{
          name: 'th1',
          value: 'thv1',
        }],
        body: [{
          name: 'tb1',
          value: 'tbv1',
        }],
      },
    };
    it('returns a string', () => {
      const result = applyCustomSettingsBody('', customData);
      assert.typeOf(result, 'string');
    });

    it('returns the same string when no settings', () => {
      const result = applyCustomSettingsBody('', {});
      assert.equal(result, '');
    });

    it('returns params in query string.', () => {
      const result = applyCustomSettingsBody('', customData);
      assert.equal(result, '&tb1=tbv1');
    });
  });

  describe('applyCustomSettingsHeaders()', () => {
    const customData = {
      auth: {
        parameters: [{
          name: 'aqp1',
          value: 'aqQv1',
        }],
      },
      token: {
        parameters: [{
          name: 'tqp1',
          value: 'tqQv1',
        }],
        headers: [{
          name: 'th1',
          value: 'thv1',
        }],
        body: [{
          name: 'tb1',
          value: 'tbv1',
        }],
      },
    };
    it('adds new headers', () => {
      const headers = { 'test': true };
      const result = applyCustomSettingsHeaders(headers, customData);
      assert.equal(result.th1, 'thv1');
    });

    it('returns the same headers object', () => {
      const headers = { 'test': true };
      const result = applyCustomSettingsHeaders(headers, {});
      assert.isTrue(result === headers);
    });

    it('returned object is a copy', () => {
      const headers = { 'test': true };
      const result = applyCustomSettingsHeaders(headers, customData);
      assert.isFalse(result === headers);
    });
  });
});
