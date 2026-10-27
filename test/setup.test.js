const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { options, assetName, verifyChecksum, resolveVersion, install, run } = require('../src/setup');

const inputs = values => name => values[name] || '';
const oidcEnv = () => ({ ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.com/oidc', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-request' });
function harness(values = {}, env = oidcEnv(), responses = []) {
  const events = [];
  const calls = [];
  const core = Object.fromEntries(['error', 'addPath', 'setOutput', 'exportVariable', 'setSecret', 'info'].map(method => [method, (...args) => events.push([method, ...args])]));
  core.getInput = inputs(values);
  return { events, calls, deps: { core, env, install: async version => ({ directory: '/tmp/synthetic', executable: '/tmp/synthetic/flint' }), execute: async (...args) => { calls.push(args); return responses.shift() || { exitCode: 0, stdout: JSON.stringify({ data: { merchant_id: 'mer_example', environment: 'sandbox', auth_type: 'workload_identity' } }) }; } } };
}

test('validates input before downloads and normalizes version and origin', () => {
  assert.equal(options(inputs({ version: 'cli/v0.12.0' })).version, '0.12.0');
  assert.equal(options(inputs({ 'api-base-url': 'https://example.com/' })).audience, 'https://example.com');
  assert.equal(options(inputs({ 'api-base-url': 'http://127.0.0.1:8080' })).baseUrl, 'http://127.0.0.1:8080');
  for (const version of ['../../x', 'cli/v1.0', '1.2.3;echo', '1.2.3-beta.1']) assert.throws(() => options(inputs({ version })));
  for (const url of ['http://example.com', 'https://user:secret@example.com', 'https://example.com/path', 'https://example.com?x=y', 'file:///tmp']) assert.throws(() => options(inputs({ 'api-base-url': url })));
  assert.throws(() => options(inputs({ verify: 'yes' })));
  assert.throws(() => options(inputs({ 'workload-identity-id': 'wid_a', 'federated-credential-id': 'wid_b' })));
  assert.equal(options(inputs({ 'federated-credential-id': 'wid_example' })).workloadIdentityId, 'wid_example');
});

test('supports all CLI runner assets and rejects unsupported platforms', () => {
  for (const platform of ['linux', 'darwin']) for (const arch of ['x64', 'arm64']) assert.match(assetName('0.12.0', platform, arch), /\.tar.gz$/);
  assert.equal(assetName('0.12.0', 'win32', 'x64'), 'flint_0.12.0_windows_amd64.zip');
  assert.throws(() => assetName('0.12.0', 'win32', 'arm64'));
  assert.throws(() => assetName('0.12.0', 'linux', 'ia32'));
});

test('latest uses the actual CLI release tag format', async () => {
  assert.equal(await resolveVersion('latest', async () => ({ ok: true, json: async () => ({ tag_name: 'cli/v0.12.0' }) })), '0.12.0');
  await assert.rejects(resolveVersion('latest', async () => ({ ok: false })));
  await assert.rejects(resolveVersion('latest', async () => ({ ok: true, json: async () => ({ tag_name: '../../invalid' }) })));
});

test('checks SHA-256 for the exact asset and rejects corrupt or ambiguous manifests', () => {
  const bytes = Buffer.from('synthetic archive');
  const hash = createHash('sha256').update(bytes).digest('hex');
  verifyChecksum(bytes, `${hash}  archive.tar.gz\n`, 'archive.tar.gz');
  for (const manifest of [`${hash}  other.tar.gz`, `${'0'.repeat(64)}  archive.tar.gz`, `${hash}  archive.tar.gz\n${hash}  archive.tar.gz`]) assert.throws(() => verifyChecksum(bytes, manifest, 'archive.tar.gz'));
});

test('never extracts a corrupt download', async () => {
  let extracted = false;
  await assert.rejects(install('0.12.0', {
    platform: 'linux', arch: 'x64',
    cache: { downloadTool: async url => url, extractTar: async () => { extracted = true; } },
    fs: { readFile: async (file, encoding) => encoding ? 'invalid checksums' : Buffer.from('bad archive') },
  }));
  assert.equal(extracted, false);
});

test('requires id-token permission when an identity is selected', async () => {
  const h = harness({ version: '0.12.0', 'workload-identity-id': 'wid_example' }, {});
  await assert.rejects(run(h.deps));
  assert.equal(h.calls.length, 0);
  assert.match(h.events[0][1], /id-token: write/);
});

test('exports identity settings and verified context without exporting a token by default', async () => {
  const h = harness({ version: '0.12.0', 'workload-identity-id': 'wid_example', scope: 'customers.read', 'api-base-url': 'https://api.staging.withflintpay.com' }, { ...oidcEnv(), FLINT_API_KEY: 'synthetic-old', FLINT_ACCESS_TOKEN: 'synthetic-old' });
  await run(h.deps);
  assert.equal(h.calls.length, 1);
  assert.equal(h.deps.env.FLINT_WORKLOAD_IDENTITY_ID, 'wid_example');
  assert.equal(h.deps.env.FLINT_OIDC_SOURCE, 'github_actions');
  assert.equal(h.deps.env.FLINT_OIDC_AUDIENCE, 'https://api.staging.withflintpay.com');
  assert.equal(h.deps.env.FLINT_OIDC_SCOPE, 'customers.read');
  assert.equal(h.deps.env.FLINT_API_KEY, '');
  assert.equal(h.deps.env.FLINT_ACCESS_TOKEN, '');
  assert.ok(h.events.some(event => event[0] === 'setOutput' && event[1] === 'auth-type' && event[2] === 'workload_identity'));
  assert.equal(h.events.some(event => event[0] === 'setSecret'), false);
  assert.equal(h.calls[0][2].silent, true);
  assert.deepEqual(h.calls[0][1], ['auth', 'status', '--output', 'json', '--no-input']);
});

test('verify false supports installation only without credentials', async () => {
  const h = harness({ version: '0.12.0', verify: 'false' }, {});
  await run(h.deps);
  assert.equal(h.calls.length, 0);
});

test('access token export is opt-in, masked before export, and stdout stays silent', async () => {
  const h = harness({ version: '0.12.0', verify: 'false', 'export-access-token': 'true' }, {}, [{ exitCode: 0, stdout: '{"access_token":"fwat_synthetic"}' }]);
  await run(h.deps);
  const mask = h.events.findIndex(event => event[0] === 'setSecret');
  const output = h.events.findIndex(event => event[0] === 'exportVariable' && event[1] === 'FLINT_ACCESS_TOKEN');
  assert.ok(mask >= 0 && output > mask);
  assert.equal(h.calls[0][2].silent, true);
  assert.deepEqual(h.calls[0][1].slice(0, 2), ['auth', 'token']);
});

test('CLI errors and invalid contexts never print raw responses or tokens', async () => {
  for (const response of [{ exitCode: 1, stdout: 'synthetic-secret', stderr: 'synthetic-secret' }, { exitCode: 0, stdout: 'synthetic-secret' }, { exitCode: 0, stdout: '{"data":{"auth_type":"api_key"}}' }]) {
    const h = harness({ version: '0.12.0', 'workload-identity-id': 'wid_example' }, oidcEnv(), [response]);
    await assert.rejects(run(h.deps));
    assert.equal(JSON.stringify(h.events).includes('synthetic-secret'), false);
  }
});

test('API keys and malformed access tokens cannot be exported', async () => {
  for (const token of ['flint_test_synthetic', '', 'fwat_bad\nvalue']) {
    const h = harness({ version: '0.12.0', verify: 'false', 'export-access-token': 'true' }, {}, [{ exitCode: 0, stdout: JSON.stringify({ access_token: token }) }]);
    await assert.rejects(run(h.deps));
    assert.equal(h.events.some(event => event[0] === 'setSecret'), false);
  }
});

test('runs a downloaded executable whose runner temporary path contains spaces', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const path = require('node:path');
  if (process.platform === 'win32') return;
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'flint runner '));
  try {
    const executable = path.join(directory, 'flint');
    await fs.writeFile(executable, '#!/bin/sh\nprintf \'%s\' \'{"data":{"merchant_id":"mer_example","environment":"sandbox","auth_type":"workload_identity"}}\'\n', { mode: 0o755 });
    const h = harness({ version: '0.12.0', 'workload-identity-id': 'wid_example' });
    h.deps.install = async () => ({ directory, executable });
    delete h.deps.execute;
    await run(h.deps);
    assert.ok(h.events.some(event => event[0] === 'setOutput' && event[1] === 'merchant-id'));
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

const { exchangeAccessToken } = require('../src/setup');
const jwt = claims => 'synthetic.' + Buffer.from(JSON.stringify({aud:'https://example.com',exp:Math.floor(Date.now()/1000)+300,...claims})).toString('base64url') + '.signature';
const exchangeSettings = () => options(inputs({'workload-identity-id':'wid_example','api-base-url':'https://example.com',scope:'payments.payment_intents.read'}));
const response = (body, status=200) => ({ok:status===200,status,headers:new Headers(),json:async()=>body});

test('workload export uses RFC 8693 directly, rejects redirects, and masks both tokens', async () => {
  const calls=[],masks=[];
  const subject=jwt({});
  const token=await exchangeAccessToken(exchangeSettings(),{setSecret:v=>masks.push(v)},oidcEnv(),async(url,options)=>{
    calls.push({url:String(url),options});
    return calls.length===1 ? response({value:subject}) : response({access_token:'fwat_synthetic',token_type:'Bearer',expires_in:300});
  });
  assert.equal(token,'fwat_synthetic');
  assert.deepEqual(masks,[subject,'fwat_synthetic']);
  assert.equal(new URL(calls[0].url).searchParams.get('audience'),'https://example.com');
  assert.equal(calls[0].options.redirect,'error');
  assert.equal(calls[1].options.redirect,'error');
  const body=calls[1].options.body;
  assert.equal(body.get('subject_token'),subject);
  assert.equal(body.get('workload_identity_id'),'wid_example');
  assert.equal(body.get('scope'),'payments.payment_intents.read');
  assert.equal(body.get('grant_type'),'urn:ietf:params:oauth:grant-type:token-exchange');
});

test('wrong audience and expired OIDC tokens are never exchanged', async () => {
  for(const claims of [{aud:'https://wrong.example.com'},{exp:1}]){
    let calls=0;
    await assert.rejects(exchangeAccessToken(exchangeSettings(),{setSecret(){}},oidcEnv(),async()=>{calls++;return response({value:jwt(claims)});}));
    assert.equal(calls,1);
  }
});

test('token export retries transient rejection, honors Retry-After, and refuses invalid bearer responses', async () => {
  let calls=0;
  const transient={...response({},429),headers:new Headers({'Retry-After':'0'})};
  const token=await exchangeAccessToken(exchangeSettings(),{setSecret(){}},oidcEnv(),async()=>{calls++;return calls===1?response({value:jwt({})}):calls===2?transient:response({access_token:'fwat_synthetic',token_type:'Bearer',expires_in:300});});
  assert.equal(calls,3);
  assert.equal(token,'fwat_synthetic');
  for(const invalid of [{access_token:'flint_test_synthetic',token_type:'Bearer',expires_in:300},{access_token:'fwat_synthetic',token_type:'Bearer',expires_in:0}]){
    let n=0;
    await assert.rejects(exchangeAccessToken(exchangeSettings(),{setSecret(){}},oidcEnv(),async()=>++n===1?response({value:jwt({})}):response(invalid)));
  }
});

test('workload export works with CLI 0.12 without invoking auth token', async()=>{
  const h=harness({version:'0.12.0',verify:'false','workload-identity-id':'wid_example','export-access-token':'true','api-base-url':'https://example.com'});
  let calls=0;
  h.deps.fetch=async()=>++calls===1?response({value:jwt({})}):response({access_token:'fwat_synthetic',token_type:'Bearer',expires_in:300});
  await run(h.deps);
  assert.equal(h.calls.length,0);
  assert.equal(h.deps.env.FLINT_ACCESS_TOKEN,'fwat_synthetic');
});
