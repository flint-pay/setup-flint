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

async function exchangeAccessToken(settings, actions, env, fetcher = fetch) {
  const url = new URL(env.ACTIONS_ID_TOKEN_REQUEST_URL);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('GitHub OIDC endpoint must use HTTPS.');
  }
  url.searchParams.set('audience', settings.audience);
  const identityResponse = await fetcher(url, {
    headers: { Authorization: `Bearer ${env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` },
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  if (!identityResponse.ok) throw new Error('GitHub OIDC request failed.');
  const identity = await identityResponse.json();
  if (typeof identity.value !== 'string') throw new Error('GitHub did not return an OIDC token.');
  actions.setSecret(identity.value);
  const parts = identity.value.split('.');
  if (parts.length !== 3 || identity.value.length > 8192) throw new Error('Invalid OIDC token.');
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  const audience = Array.isArray(claims.aud) && claims.aud.length === 1 ? claims.aud[0] : claims.aud;
  if (audience !== settings.audience || !Number.isFinite(claims.exp) || claims.exp <= Date.now() / 1000) {
    throw new Error('OIDC token audience or lifetime does not match the request.');
  }
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: identity.value,
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    workload_identity_id: settings.workloadIdentityId,
  });
  if (settings.scope) form.set('scope', settings.scope);
  for (let attempt = 0; attempt < 3; attempt++) {
    const response = await fetcher(`${settings.baseUrl}/v1/oauth/token`, {
      method: 'POST', body: form, headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirect: 'error', signal: AbortSignal.timeout(10000),
    });
    if (response.ok) {
      const result = await response.json();
      if (typeof result.access_token === 'string') actions.setSecret(result.access_token);
      if (result.token_type?.toLowerCase() !== 'bearer' || !Number.isFinite(result.expires_in) || result.expires_in <= 0 || !/^fwat_[A-Za-z0-9_-]+$/.test(result.access_token || '')) {
        throw new Error('Invalid workload access token response.');
      }
      return result.access_token;
    }
    if (attempt === 2 || (response.status !== 429 && response.status < 500)) break;
    const retry = response.headers.get('retry-after');
    const milliseconds = retry ? (/^\d+(?:\.\d+)?$/.test(retry) ? Number(retry) * 1000 : Date.parse(retry) - Date.now()) : 250 * 2 ** attempt;
    // A long retry window needs a new workflow attempt, rather than retrying early.
    if (!Number.isFinite(milliseconds) || milliseconds > 10000) break;
    await new Promise(resolve => setTimeout(resolve, Math.max(0, milliseconds)));
  }
  throw new Error('Workload token exchange failed.');
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
    const result = await execute(`"${binary.executable}"`, [...args, '--output', 'json', '--no-input'], {
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
    let token;
    if (settings.workloadIdentityId) {
      try { token = await exchangeAccessToken(settings, actions, env, deps.fetch || fetch); }
      catch {
        actions.error('Could not export a workload access token. Check OIDC permission, identity trust, audience, scopes, and API availability.');
        throw new Error('Workload access token export failed');
      }
    } else if (env.FLINT_ACCESS_TOKEN) {
      token = env.FLINT_ACCESS_TOKEN;
    } else {
      const response = await cli(['auth', 'token']);
      token = response.access_token || response.data?.access_token;
    }
    if (typeof token !== 'string' || !/^(fwat_|fcat_)[A-Za-z0-9_-]+$/.test(token)) {
      actions.error('Flint did not return an exportable access token. API keys cannot be exported.');
      throw new Error('No exportable access token');
    }
    actions.setSecret(token);
    exportVariable('FLINT_ACCESS_TOKEN', token);
  }
  actions.info(`Flint CLI ${version} is ready.`);
}

module.exports = { options, assetName, verifyChecksum, resolveVersion, install, exchangeAccessToken, run };
