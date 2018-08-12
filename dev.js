const srv = require('./test/implicit-server.js');

srv.create()
.then((port) => {
  console.log('Listening on ', port);
});
