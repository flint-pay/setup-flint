const core = require('@actions/core');
const tc = require('@actions/tool-cache');
const exec = require('@actions/exec');
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');

const REPOSITORY = 'flint-pay/flint-cli';

function options(input) {
  const version = input('version') || 'latest';
  if (version !== 'latest' && !/^(?:cli\/)?v?\d+\.\d+\.\d+$/.test(version)) {
    throw new Error('version must be latest or a stable CLI version such as 0.12.0.');
  }
  const identity = input('workload-identity-id');
  const alias = input('federated-credential-id');
  if (identity && alias && identity !== alias) throw new Error('The two workload identity inputs must match.');
  const workloadIdentityId = identity || alias;
  if (workloadIdentityId && !/^wid_[A-Za-z0-9_-]+$/.test(workloadIdentityId)) {
    throw new Error('workload-identity-id must be a Flint workload identity ID (wid_...).');
  }
  let url;
  try { url = new URL(input('api-base-url') || 'https://api.withflintpay.com'); }
  catch { throw new Error('api-base-url must be an HTTPS origin or a loopback HTTP origin.'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('api-base-url must be an HTTPS origin or a loopback HTTP origin.');
  }
  const boolean = (name, fallback) => {
    const value = input(name) || fallback;
    if (!['true', 'false'].includes(value)) throw new Error(`${name} must be true or false.`);
    return value === 'true';
  };
  return {
    version: version.replace(/^cli\//, '').replace(/^v/, ''),
    workloadIdentityId, baseUrl: url.origin,
    audience: input('audience') || url.origin, scope: input('scope'),
    verify: boolean('verify', 'true'), exportToken: boolean('export-access-token', 'false'),
  };
}

function assetName(version, platform, arch) {
  const os = { linux: 'linux', darwin: 'darwin', win32: 'windows' }[platform];
  const cpu = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!os || !cpu || (platform === 'win32' && arch !== 'x64')) {
    throw new Error('Supported runners: Linux and macOS x64/arm64, and Windows x64.');
  }
  return `flint_${version}_${os}_${cpu}.${platform === 'win32' ? 'zip' : 'tar.gz'}`;
}

function verifyChecksum(bytes, checksums, name) {
  const matches = checksums.split(/\r?\n/).map(line => line.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/)).filter(match => match && match[2] === name);
  const actual = crypto.createHash('sha256').update(bytes).digest('hex');
  if (matches.length !== 1 || matches[0][1].toLowerCase() !== actual) {
    throw new Error('CLI archive SHA-256 verification failed.');
  }
}

async function resolveVersion(version, fetcher = fetch) {
  if (version !== 'latest') return version;
  const response = await fetcher(`https://api.github.com/repos/${REPOSITORY}/releases/latest`, {
    headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'setup-flint' },
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error('Could not resolve the latest CLI release. Pin the version input or retry.');
  const release = await response.json();
  if (!/^cli\/v\d+\.\d+\.\d+$/.test(release.tag_name)) throw new Error('Latest CLI release has an unsupported version tag.');
  return release.tag_name.slice(5);
}

async function install(version, deps = {}) {
  const cache = deps.cache || tc;
  const filesystem = deps.fs || fs;
  const platform = deps.platform || process.platform;
  const arch = deps.arch || process.arch;
  const name = assetName(version, platform, arch);
  const url = `https://github.com/${REPOSITORY}/releases/download/cli/v${version}`;
  // Verify on every run, including self-hosted runners, rather than trusting a cache.
  const archive = await cache.downloadTool(`${url}/${name}`);
  const checksums = await cache.downloadTool(`${url}/checksums.txt`);
  verifyChecksum(await filesystem.readFile(archive), await filesystem.readFile(checksums, 'utf8'), name);
  const extracted = platform === 'win32' ? await cache.extractZip(archive) : await cache.extractTar(archive);
  const executable = path.join(extracted, platform === 'win32' ? 'flint.exe' : 'flint');
  await filesystem.access(executable);
  if (platform !== 'win32') await filesystem.chmod(executable, 0o755);
  return { directory: extracted, executable };
}

async function run(deps = {}) {
  const actions = deps.core || core;
  const env = deps.env || process.env;
  const execute = deps.execute || exec.getExecOutput;
  let settings;
  try { settings = options(name => actions.getInput(name).trim()); }
  catch (error) { actions.error(error.message); throw error; }
  if (settings.workloadIdentityId && (!env.ACTIONS_ID_TOKEN_REQUEST_URL || !env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {
    actions.error('Workload identity requires permissions: id-token: write on this job.');
    throw new Error('OIDC permission missing');
  }
  let version;
  let binary;
  try {
    version = await resolveVersion(settings.version, deps.fetch || fetch);
    binary = await (deps.install || install)(version);
  } catch {
    actions.error('Could not install the Flint CLI. Check the version, runner platform, release assets, and network access.');
    throw new Error('CLI installation failed');
  }
  actions.addPath(binary.directory);
  actions.setOutput('flint-version', version);
  const exportVariable = (name, value) => { actions.exportVariable(name, value); env[name] = value; };
  exportVariable('FLINT_BASE_URL', settings.baseUrl);
  if (settings.workloadIdentityId) {
    // An explicitly selected workload identity must take precedence over ambient credentials.
    for (const name of ['FLINT_API_KEY', 'FLINT_ACCESS_TOKEN']) exportVariable(name, '');
    exportVariable('FLINT_WORKLOAD_IDENTITY_ID', settings.workloadIdentityId);
    exportVariable('FLINT_OIDC_SOURCE', 'github_actions');
    exportVariable('FLINT_OIDC_AUDIENCE', settings.audience);
    exportVariable('FLINT_OIDC_SCOPE', settings.scope);
    exportVariable('FLINT_CLI_CREDENTIALS', '0');
  }
  async function cli(args) {
    const result = await execute(`"${binary.executable}"`, [...args, '--output', 'json', '--no-input', '--base-url', settings.baseUrl], {
      silent: true, ignoreReturnCode: true, env,
    });
    // Neither stdout nor stderr is logged: auth token output contains credentials.
    if (result.exitCode !== 0) {
      try {
        const code = JSON.parse(result.stdout).error?.code;
        if (typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(code)) actions.error(`Flint CLI error code: ${code}`);
      } catch {}
      actions.error('Flint authentication failed. Check id-token: write, the workload identity trust conditions, audience, scopes, and API URL.');
      throw new Error('Flint authentication failed');
    }
    try { return JSON.parse(result.stdout); }
    catch { throw new Error('The CLI returned an invalid JSON response.'); }
  }
  if (settings.verify) {
    const response = await cli(['auth', 'status']);
    const context = response.data;
    if (!context || !context.merchant_id || !context.environment || !context.auth_type || (settings.workloadIdentityId && context.auth_type !== 'workload_identity')) {
      actions.error('Flint returned an unexpected authentication context.');
      throw new Error('Invalid auth context');
    }
    for (const [output, field] of [['merchant-id', 'merchant_id'], ['environment', 'environment'], ['auth-type', 'auth_type']]) {
      actions.setOutput(output, context[field]);
    }
  }
  if (settings.exportToken) {
    const response = await cli(['auth', 'token']);
    const token = response.access_token || response.data?.access_token;
    if (typeof token !== 'string' || !/^(fwat_|fcat_)[A-Za-z0-9_-]+$/.test(token)) {
      actions.error('Flint did not return an exportable access token. API keys cannot be exported.');
      throw new Error('No exportable access token');
    }
    actions.setSecret(token);
    exportVariable('FLINT_ACCESS_TOKEN', token);
  }
  actions.info(`Flint CLI ${version} is ready.`);
}

module.exports = { options, assetName, verifyChecksum, resolveVersion, install, run };
