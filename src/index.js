const core = require('@actions/core');
const { run } = require('./setup');
run().catch(() => core.setFailed('Flint setup failed. See the preceding diagnostic.'));
