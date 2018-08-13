# Renderer process proxy

This small library handles `oauth2-token-requested` custom event dispatches in
the renderer process and communicates with main process using ipc.

ARC components uses `oauth2-token-requested` to request for the token from hosting
application. This is a class that creates a proxy for the components.

## Usage

```javascript
const {OAuth2Handler} = require('@advanced-rest-client/electron-oauth2/renderer');
const proxy = new OAuth2Handler();
proxy.listen();

...
// Somewhere in the application, from a web component
this.dispatchEvent(new CustomEvent('oauth2-token-requested', {
  bubbles: true,
  composed: true,
  cancelable: true,
  detail: {
    state: 'abcd',
    ...
  }
}));
```

To listen for the response, listen for `oauth2-token-response` and `oauth2-error`
web custom events.

```javascript
window.addEventListener('oauth2-token-response', (e) => {
  if (e.detail.state !== 'abcd') {
    return;
  }
  console.log(e.detail);
});
window.addEventListener('oauth2-error', (e) => {
  if (e.detail.state !== 'abcd') {
    return;
  }
  console.error(e.detail);
});
```
