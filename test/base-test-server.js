// jscs:disable requireCamelCaseOrUpperCaseIdentifiers
const http = require('http');
const { URLSearchParams } = require('url');

class TestBaseServer {
  constructor() {
    this.server = undefined;
    this.socketMap = {};
    this.lastSocketKey = 0;
    this._handleConnection = this._handleConnection.bind(this);
    this._handleRequest = this._handleRequest.bind(this);
    this.responseType = undefined;
    this.token = undefined;
    this.expiresIn = undefined;
    this.code = undefined;
    this.refreshToken = undefined;
    this.tokenType = undefined;
  }

  _handleConnection(socket) {
    const socketKey = ++this.lastSocketKey;
    this.socketMap[socketKey] = socket;
    socket.on('close', () => {
      delete this.socketMap[socketKey];
    });
  }

  _handleRequest(req, res) {
    if (req.method === 'GET' && req.url.indexOf('/auth/popup') === 0) {
      this.handleAuthorizationPopup(res);
      return;
    }
    if (req.method === 'GET' && req.url.indexOf('/auth') === 0) {
      this.handleAuthorizationRequest(req, res);
      return;
    }
    if (req.method === 'POST' && req.url.indexOf('/token') === 0) {
      this.handleAuthorizationToken(req, res);
      return;
    }
    res.writeHead(500, { 'Content-Type': 'text/html' });
    res.write(`URL ${req.url} not handled`);
    res.end();
  }

  create() {
    return new Promise((resolve) => {
      const server = http.createServer(this._handleRequest);
      server.on('error', (err) => {
        throw err;
      });
      server.listen(0, () => {
        // @ts-ignore
        const { port } = server.address();
        resolve(port);
      });
      server.on('connection', this._handleConnection);
      this.server = server;
    });
  }

  shutdown() {
    Object.keys(this.socketMap).forEach((socketKey) =>
      this.socketMap[socketKey].destroy());
    return new Promise((resolve) => {
      this.server.close(() => resolve());
    });
  }

  redirectError(redirectUrl, res, code, message) {
    redirectUrl += `&error=${ code}`;
    redirectUrl += `&error_description=${ encodeURIComponent(message)}`;
    res.writeHead(301, {
      'Location': redirectUrl,
    });
    res.end();
  }

  handleAuthorizationPopup(res) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    let body = '<!DOCTYPE html><html lang="en"><head></head>';
    body += '<body><h1>Popup redirect</h1>';
    body += '<script>';
    body += 'document.write(\'<p>\' + location.href + \'</p>\')';
    body += '</script>';
    body += '</body></html>';
    res.write(body);
    res.end();
  }

  handleAuthorizationRequest(req, res) {
    const params = req.url.substr(req.url.indexOf('?') + 1);
    const oauthParams = new URLSearchParams(params);

    if (oauthParams.get('custom_no_session')) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.write('<!DOCTYPE html><html lang="en"><head></head><body></body></html>');
      res.end();
      return;
    }
    const delimiter = this.responseType === 'token' ? '#' : '?';
    const type = oauthParams.get('response_type');
    let redirectUri = oauthParams.get('redirect_uri');
    redirectUri += `${delimiter }state=${ oauthParams.get('state')}`;
    if (type !== this.responseType) {
      this.redirectError(redirectUri, res, 'invalid_grant', 'Grand type not supported');
      return;
    }
    if (oauthParams.get('custom_report_error')) {
      this.redirectError(redirectUri, res, 'test-error', 'test-error-message');
      return;
    }
    if (this.responseType === 'token') {
      redirectUri += `&access_token=${this.token}`;
      redirectUri += '&token_type=bearer';
      redirectUri += `&expires_in=${this.expiresIn}`;
      if (oauthParams.get('custom_scope')) {
        redirectUri += '&scope=scope1+scope2';
      }
    } else {
      redirectUri += `&code=${this.code}`;
    }
    if (oauthParams.get('custom_delay_response')) {
      let body = '<!DOCTYPE html><html lang="en"><head>';
      body += `<meta http-equiv="refresh" content="2;url=${redirectUri}"/>`;
      body += '</head>';
      body += '<body><h1>Oauth provider</h1>';
      body += '</body></html>';
      res.write(body);
      res.end();
      return;
    }
    res.writeHead(301, {
      'Location': redirectUri,
    });
    res.end();
  }

  _reportJsonError(res, error, message) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.write(JSON.stringify({
      error,
      message,
    }));
    res.end();
  }

  handleAuthorizationToken(req, res) {
    const accept = req.headers.accept || 'application/json';
    const body = [];
    req
      .on('data', (chunk) => {
        body.push(chunk);
      })
      .on('end', () => {
        const parsedBody = Buffer.concat(body).toString();
        const oauthParams = new URLSearchParams(parsedBody);
        const type = oauthParams.get('grant_type');
        if (['authorization_code', 'password', 'client_credentials'].indexOf(type) === -1) {
          this._reportJsonError(res, 'invalid_grant', `Grant type "${type}" is invalid`);
          return;
        }
        if (oauthParams.get('custom_fail_request')) {
          this._reportJsonError(res, 'custom_fail_request', 'Forced fail');
          return;
        }
        if (type === 'authorization_code') {
          const code = oauthParams.get('code');
          if (code !== this.code) {
            this._reportJsonError(res, 'invalid_code', 'Code is invalid');
            return;
          }
          const redirectUri = oauthParams.get('redirect_uri');
          if (!redirectUri) {
            this._reportJsonError(res, 'invalid_redirect_uri', 'redirect_uri invalid');
            return;
          }
          const clientId = oauthParams.get('client_id');
          if (!clientId) {
            this._reportJsonError(res, 'invalid_client_id', 'client_id invalid');
            return;
          }
        }
        if (type === 'password') {
          if (!oauthParams.get('password')) {
            this._reportJsonError(res, 'password_missing', 'password is missing');
            return;
          }
          if (!oauthParams.get('username')) {
            this._reportJsonError(res, 'username_missing', 'username is missing');
            return;
          }
        }
        const params = {
          access_token: this.token,
          token_type: this.tokenType,
          expires_in: this.expiresIn,
          refresh_token: this.refreshToken,
        };
        if (oauthParams.get('custom_test_body')) {
          params.custom_test_body = true;
        }
        if (oauthParams.get('custom_test_url')) {
          const uParams = new URLSearchParams(req.url.substr(req.url.indexOf('?') + 1));
          if (uParams.get('custom_test_url')) {
            params.custom_test_url = true;
          }
        }
        if (oauthParams.get('custom_test_headers')) {
          if (req.headers['x-custom-test-headers']) {
            params.custom_test_headers = true;
          }
        }
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
module.exports.TestBaseServer = TestBaseServer;
