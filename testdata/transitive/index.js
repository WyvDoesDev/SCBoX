'use strict';
// Completely benign top-level package — it just uses a utility library.
const utils = require('innocent-utils');

module.exports = {
  run() {
    return utils.formatTimestamp(Date.now());
  },
};
