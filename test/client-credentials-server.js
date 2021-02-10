const { TestBaseServer } = require('./base-test-server');

class ClientCredentialsServer extends TestBaseServer {
  constructor() {
    super();
    this.token = 'test-cc-token';
    this.tokenType = 'test-cc-type';
    this.code = 'test-cc-response';
    this.expiresIn = 900;
    this.responseType = 'cc-bearer';
    this.refreshToken = 'cc-refresh-token';
  }

  handleAuthorizationToken(req, res) {
    const { authorization, accept = 'application/json' } = req.headers;
    // if (!authorization) {
    //   this._reportJsonError(res, 'invalid_request', `authorization header not set`);
    //   return;
    // }
    const body = [];
    req.on('data', (chunk) => {
      body.push(chunk);
    }).on('end', () => {
      const parsedBody = Buffer.concat(body).toString();
      const oauthParams = new URLSearchParams(parsedBody);
      const type = oauthParams.get('grant_type');
      if ('client_credentials' !== type) {
        this._reportJsonError(res, 'invalid_grant', `Grant type "${type}" is invalid`);
        return;
      }

      let clientId = oauthParams.get('client_id');
      let clientSecret = oauthParams.get('client_secret');
      if (!clientId || !clientSecret) {
        if (!authorization) {
          this._reportJsonError(res, 'invalid_request', 'no client credentials provided');
          return;
        }
        const hash = authorization.replace(/basic /i, '');
        const unHashed = Buffer.from(hash, 'base64').toString();
        [clientId, clientSecret] = unHashed.split(':');
      }
      if (!clientId) {
        this._reportJsonError(res, 'invalid_request', 'client_id invalid');
        return;
      }
      if (!clientSecret) {
        this._reportJsonError(res, 'invalid_request', 'client_secret invalid');
        return;
      }
      const params = {
        access_token: this.token,
        token_type: this.tokenType,
        expires_in: this.expiresIn,
        refresh_token: this.refreshToken,
      };
      let returnBody = '';
      if (accept === 'application/json') {
        returnBody = JSON.stringify(params);
      } else {
        returnBody = Object.keys(params)
          .map((key) => `${encodeURIComponent(key)}=${encodeURIComponent(params[key])}`)
          .join('&');
      }
      res.writeHead(200, { 'Content-Type': accept });
      res.write(returnBody);
      res.end();
    });
  }
}

const instance = new ClientCredentialsServer();

module.exports = {
  create() {
    return instance.create();
  },
  shutdown() {
    return instance.shutdown();
  },
};
