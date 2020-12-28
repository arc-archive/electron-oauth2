/**
 * @param {number=} timeout
 * @return {Promise<void>}
 */
async function aTimeout(timeout) {
  return new Promise((resolve) => {
    setTimeout(resolve, timeout);
  });
}

module.exports.aTimeout = aTimeout;
