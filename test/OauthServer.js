const { OAuth2Server } = require('oauth2-mock-server');
const getPort = require('get-port');

const oauth2server = new OAuth2Server();

/**
 * @return {Promise<any>}
 */
module.exports.startServer = async function() {
  const port = await getPort({ port: getPort.makeRange(8000, 8100) });
  const jwtKey = await oauth2server.issuer.keys.generate('RSA256');
  await oauth2server.start(port, 'localhost');
  return {
    port,
    jwtKey,
    issuer: oauth2server.issuer.url,
  };
};

/**
 * @return {Promise<void>}
 */
module.exports.stopServer = async function() {
  await oauth2server.stop();
};
