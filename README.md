# OAuth 2 authorization library for Electron application

This library originally was created for Advanced REST Client application.
It is shared under Apache 2.0 license.

A library to manage OAuth2 identities. It runs in the main process of the electron application and listens to the events on main IPC to start the OAuth flow.

## Usage

```sh
npm i @advanced-rest-client/electron-oauth2
```

In your main class:

```javascript
import { Oauth2Identity } from '@advanced-rest-client/electron-oauth2';
Oauth2Identity.listen();
```

Requesting token from the renderer process:

```javascript
const { ipcRenderer } = require('electron');

const config = {
  interactive: true,
  type: 'implicit',
  scopes: ['email', 'profile'],
  clientId: 'client-id',
  authorizationUri: 'https://auth.domain.com/auth',
  redirectUri: 'https://my.domain.com/oauth2callback',
  state: 'RANDOM',
};

try {
  const tokenInfo = await ipcRenderer.invoke('oauth2-launchwebflow', config);
  console.log(tokenInfo);
} catch (cause) {
  console.error(cause);
}
```

### ARC events

This module contains a class for the renderer process that handles events defined in `@advanced-rest-client/arc-events`. Use them in the web application (in the renderer process) to request for the token.

#### In the preload script

```javascript
import { Oauth2Identity } from '@advanced-rest-client/electron-oauth2/renderer/OAuth2Handler.js';
process.once('loaded', () => {
  const oauthBridge = new Oauth2Identity();
  oauthBridge.listen();
});
```

#### Anywhere in the renderer process

```javascript
import { AuthorizationEvents } from '@advanced-rest-client/arc-events';

try {
  const tokenInfo = await AuthorizationEvents.OAuth2.authorize(document.body, { ...config });
} catch (e) {
  // ...
}
```

### TokenInfo object

The token info object returned by the authorization flow.
Contains OAuth2 properties returned by the OAuth server with camel case
representation of each property.

#### access_token

String. Token value.
Also available under `accessToken` key.

#### token_type

String. Token type. This parameter is required by OAuth 2 spec to be returned by the server.
Also available under `tokenType` key.

#### state

String. The state parameter returned by the server. When client don't specify state parameter the library adds its own generated state. The response is checked for the state and error is reported if the state do not match.

#### expires_in

Number. Returned by the server `expires_in` parameter. Number of seconds when
token expires. If not received by the server it assumes 3600 seconds. When this
happens the `expiresAssumed` is set on the token info object.

Also available under `expiresIn` key.

#### expires_at

Number. Timestamp when the token expires. It is based on `expiresIn` property.
If the authorization server did not returned `expiresIn` property it assumes
3600 seconds (1 hour). Because this time is computed after the response is
recorded it may be different from what server recorded +- few seconds.

Also available under `expiresAt` key.

#### scope

Array of strings. This parameter is optional if the list of granted scopes is identical to requested scopes. Otherwise it's required.

### Interactive flag

OAuth flow with `interactive` option set to `false` allows to quietly request for the token from the cache or form the authorization server without notifying the user (without bringing the authorization pop-up).

This is to be used to check if valid session exists for current user and update the UI accordingly.

Note, when `interactive` is `false` the `oauth-2-token-ready` is dispatched even if session do not exists. In this case `tokenInfo` has different structure:

```json
{
  "interactive": false,
  "code": "not_authorized",
  "state": "request state parameter value"
}
```

## Grant types configuration

OAuth 2 specification defined 4 basic OAuth flows and allows to extend the spec by using custom grants. This section describe parameters for each flow.

Each flow recognizes two sets of parameters. It doesn't matter which one is used or
if it's mixed. The reason is described in [Application wide OAuth configuration](#application-wide-oauth-configuration).

### Implicit

**type** is always `implicit`.

**clientId** is OAuth provided client id.

**authorizationUri** is OAuth provider authorization pop-up URI.

**redirectUri** is configured redirect URI for client. This is usually configurable by the user in provider's settings.

**scopes** Is a list of scopes to authorize.

**state** If not set it's auto generated. The library checks for the state parameter and reports error when state do not match.

**interactive** See [Interactive flag](#interactive-flag) description.

**includeGrantedScopes** When `true`, it adds `include_granted_scopes` parameter to the authorization URI. This is not standard OAuth2 parameter. Google authorization server uses it to include previously granted OAuth scopes for this OAuth client in the new authorization granted OAuth scopes.

**loginHint** Set to an email value of recognized user. This is not standard OAuth2 parameter. Google authorization server uses it to render consent screen for the user without asking to select the user if the user has more than one identity.

```json
{
  "type": "implicit",
  "clientId": "String, required",
  "authorizationUri": "String, required",
  "redirectUri": "String, optional",
  "scopes": "Array<String>, optional",
  "state": "String, optional",
  "interactive": "Boolean, optional",
  "includeGrantedScopes": "Boolean, optional",
  "loginHint": "String, optional"
}
```

### Code

**type** is always `authorization_code`.

**clientId** is OAuth configuration provided client id.

**clientSecret** is OAuth configuration provided client secret.

**authorizationUri** is OAuth configuration provider authorization pop-up URI.

**accessTokenUri** is OAuth configuration provider code exchange URI.

**redirectUri** is configured redirect URI for client. This is usually configurable by the user in provider's settings.

**scopes** Is a list of scopes to authorize.

**state** If not set it's auto generated. The library checks for the state parameter and reports error when state do not match.

**interactive** See [Interactive flag](#interactive-flag) description.

**include_granted_scopes** When `true`, it adds `include_granted_scopes` parameter to the authorization URI. This is not standard OAuth2 parameter. Google authorization server uses it to include previously granted OAuth scopes for this OAuth client in the new authorization granted OAuth scopes.

**login_hint** Set to an email value of recognized user. This is not standard OAuth2 parameter. Google authorization server uses it to render consent screen for the user without asking to select the user if the user has more than one identity.

```json
{
  "type": "authorization_code",
  "clientId": "String, required",
  "clientSecret": "String, optional",
  "authorizationUri": "String, required",
  "accessTokenUri": "String, required",
  "redirectUri": "String, optional",
  "scopes": "Array<String>, optional",
  "state": "String, optional",
  "interactive": "Boolean, optional",
  "include_granted_scopes": "Boolean, optional",
  "login_hint": "String, optional"
}
```

### Password

**type** is always `password`.

**username** User login

**password** User password

**accessTokenUri** is OAuth configuration provider code exchange URI.

**scopes** Is a list of scopes to authorize.

**clientId** is OAuth configuration provided client id.

**interactive** See [Interactive flag](#interactive-flag) description.

```json
{
  "type": "password",
  "username": "String, required",
  "password": "String, required",
  "accessTokenUri": "String, required",
  "scopes": "Array<String>, optional",
  "clientId": "String, optional",
  "interactive": "Boolean, optional"
}
```

### Client credentials

**type** is always `authorization_code`.

**accessTokenUri** is OAuth configuration provider code exchange URI.

**scopes** Is a list of scopes to authorize.

**clientId** is OAuth configuration provided client id.

**clientSecret** is OAuth configuration provided client secret.

**interactive** See [Interactive flag](#interactive-flag) description.

```json
{
  "type": "client_credentials",
  "accessTokenUri": "String, required",
  "scopes": "Array<String>, optional",
  "clientId": "String, optional",
  "clientSecret": "String, optional",
  "interactive": "Boolean, optional"
}
```

### Custom grant type

This is combination of all above parameters, none of which is required.
The **type** should be set to the grant type supported by the authorization server.

## Custom authorization data

OAuth 2 specification allows to extend the protocol by providing additional data to the pop-up URI or when making a request to the authorization server with the body.

The library allows to do this by setting the `customData` property on the settings
object.

```javascript
const settings = {
  ...
  customData: {
    auth: {
      parameters: Array|undefined
    },
    token: {
      parameters: Array|undefined,
      headers: Array|undefined,
      body: Array|undefined
    }
  }
}
```

Each array item is an object with `name` and `value` properties.

The `auth` is applied to the authorization request (`implicit` and `authorization_code` grants). The `parameters` contains the list of parameters to add to the URI.

The `token` is applied to token request (`authorization_code`, `password`, and  `client_credentials` grants). Each property is applied to the corresponding fields.

### Example

```javascript
const settings = {
  ...
  customData: {
    token: {
      parameters: [{
        name: 'query param name',
        value: 'query param value'
      }],
      headers: [{
        name: 'x-custom-header',
        value: 'header value'
      }],
      body: [{
        name: 'body param name',
        value: 'body param value'
      }]
    }
  }
}
```

Note: `body` content type is always `application/x-www-form-urlencoded`.
`customData.token.body` parameters must not be url encoded. The library processes the values.

## Application wide OAuth configuration

The main use case of this library to authorize the user in many services at application runtime. However, if your application works with single OAuth 2 provider it is easier to store common configuration in single place and just provide missing data in the `settings` object.

For this the library support additional method of authorizing the user `getAuthToken()`.
The method reads `package.json` of the application and uses `oauth2` section to use it as settings when creating an instance of auth provider. This settings are always used unless the `settings` object override the values.

### Example configuration

In `package.json` file:

```json
"oauth2": {
  "response_type": "implicit",
  "client_id": "my-client-id",
  "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
  "redirect_uri": "https://auth.advancedrestclient.com/oauth2",
  "scopes": [
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.install",
    "https://www.googleapis.com/auth/drive.metadata.readonly"
  ]
}
```

Then in main process:

```javascript
const {Oauth2Identity} = require('@advanced-rest-client/electron-oauth2');
Oauth2Identity.getAuthToken()
.then((tokenInfo) => console.log(tokenInfo))
.catch((cause) => console.error(cause));
```

Or in the renderer process:

```javascript
const {ipcRenderer} = require('electron');

const requestId = 'Optional id to recognize the request in event based env';
ipcRenderer.send('oauth-2-get-token', {
  interactive: false
}, requestId);
ipcRenderer.on('oauth-2-token-ready', (e, tokenInfo, id) => {
  if (id !== requestId) {
    return;
  }
  console.log(tokenInfo);
});
ipcRenderer.on('oauth-2-token-error', (e, cause, id) => {
  if (id !== requestId) {
    return;
  }
  console.error(cause);
});
```

Parameters in json file can have different notation than in JavaScript file (underscore versus CamelCase). Therefore both configuration syntax are supported by the library.

## Handing errors

In the main process use `catch()` function of the promise returned by any of the functions.

In the renderer process listen to `oauth-2-token-error` event to handle OAuth error.

The error object contains the following properties:

```json
{
  "state": "The state request with last call (not returned by the server!)",
  "code": "Application code, eg. user_interrupted",
  "message": "Associated message with the error",
  "interactive": "Boolean. Value of the interactive flag"
}
```

### Error codes

The error code can be any of standard OAuth 2 error codes returned by the server or

- `no_state` - state parameter is missing
- `invalid_state` - the state returned by the server is not the same as requested
- `uri_error` - token request couldn't be initialized probably due malformed URL
- `user_interrupted` - the user closed pop-up window before finishing the flow
- `auth_error` - only when `interactive` flag is set to `false`. The response wasn't recorded from the server.

## Security considerations

Electron applications runs the code on the client side. There's nothing to stop the user from reading application source code. Therefore you should avoid storing `client_secret` anywhere in the application and to only use `implicit` or `password` grant type. Only this methods ensures that your application identity won't be used by unauthorized application.
