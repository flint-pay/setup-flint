# Setup Flint

Install the [Flint CLI](https://github.com/flint-pay/flint-cli) and use a GitHub Actions
OIDC token to authenticate with a Flint workload identity. No stored Flint API key is
needed.

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  payments:
    runs-on: ubuntu-latest
    steps:
      - uses: flint-pay/setup-flint@v1
        with:
          workload-identity-id: ${{ vars.FLINT_WORKLOAD_IDENTITY_ID }}
      - run: flint payment-intents list --output json
```

First create a workload identity in Flint under **Developers > Workload identities**.
Choose GitHub Actions and restrict its trust conditions to your repository, branch or
environment. Grant only the scopes your workflow needs. The workload identity ID is a
non-secret `wid_...` value, so it can be stored in a GitHub Actions variable.

## Inputs

| Input | Default | Behavior |
| --- | --- | --- |
| `version` | `latest` | Install the latest stable CLI or an exact version such as `0.12.0`. `v0.12.0` and `cli/v0.12.0` also work. |
| `workload-identity-id` | | Select a Flint workload identity. Requires `permissions: id-token: write`. |
| `federated-credential-id` | | Compatibility alias for `workload-identity-id`. If both are set, they must match. |
| `api-base-url` | `https://api.withflintpay.com` | API origin. HTTPS is required except for loopback development URLs. |
| `audience` | API origin | Audience requested from GitHub. Must match the workload identity audience. |
| `scope` | | Optional space-separated scopes to narrow the workload identity grant. |
| `verify` | `true` | Call `flint auth status` and populate the authentication outputs. Set `false` to install without checking authentication. |
| `export-access-token` | `false` | Export a masked short-lived `FLINT_ACCESS_TOKEN` for later steps. With a workload identity, uses the OAuth token-exchange endpoint directly. Exporting a saved CLI login requires a CLI release with `flint auth token`. |

When an identity is selected, the action exports `FLINT_WORKLOAD_IDENTITY_ID`,
`FLINT_OIDC_SOURCE=github_actions`, `FLINT_OIDC_AUDIENCE`, `FLINT_OIDC_SCOPE`, and
`FLINT_BASE_URL`. It clears `FLINT_API_KEY` and `FLINT_ACCESS_TOKEN` so the selected identity
is used. Credentials configured in a later step can override these environment values.
The CLI and supported SDKs request OIDC tokens and exchange them when needed.

Without an identity input, existing CLI credentials are used for verification. For
installation alone, set `verify: 'false'`.

## Outputs

| Output | Value |
| --- | --- |
| `flint-version` | Installed CLI version, such as `0.12.0`. |
| `merchant-id` | Verified merchant ID. Empty when `verify` is false. |
| `environment` | Verified Flint environment. Empty when `verify` is false. |
| `auth-type` | Authentication type, such as `workload_identity`. Empty when `verify` is false. |

## Staging and SDKs

Use `api-base-url: https://api.staging.withflintpay.com` with a staging workload identity.
A staging identity cannot authenticate against production. The identity must be active,
its trust conditions must match the GitHub job, and its API must have an active signing
key.

Node `@flintpay/node` 5.1.0 and PHP `flintpay/flint` 5.1.0 discover the exported workload
identity settings automatically:

```yaml
- uses: flint-pay/setup-flint@v1
  with:
    workload-identity-id: ${{ vars.FLINT_WORKLOAD_IDENTITY_ID }}
    api-base-url: https://api.staging.withflintpay.com
- run: node scripts/list-customers.mjs
```

Configure the SDK's API base URL explicitly when calling staging. See the
[SDK documentation](https://github.com/flint-pay/flint-sdks) for client options.

If `export-access-token` is enabled, the exported bearer token expires and is not
refreshed by the action. Later steps must finish within its lifetime. Leave it disabled
to let the CLI and SDK credential providers request fresh tokens. Access tokens are
masked before export and are never action outputs. CLI command responses used by this
action are captured without logging them.

## Runners and security

The action uses Node.js 24. It supports Linux and macOS on x64 and arm64, and Windows on
x64. Self-hosted runners need a GitHub Actions runner version that supports Node.js 24.

Each run downloads the CLI from the public Flint CLI GitHub release and verifies its
SHA-256 against that release's `checksums.txt` before extraction. Both files come from
the same release. This verifies archive integrity and depends on the release publisher's
GitHub account security. Pin `version` for a fixed CLI version and pin this action to a
commit SHA when your workflow requires an immutable action reference.

Do not run untrusted pull request code in a job allowed to use a privileged workload
identity. Restrict the identity's subject and repository ID claims and request only the
scopes the job needs.

## Development

```sh
npm ci --ignore-scripts
npm test
npm run build
git diff --exit-code -- dist
```

Commit `dist/` with source changes. CI checks the bundle and tests installation on Linux,
macOS, and Windows. Releases use immutable semantic version tags such as `v1.0.0`; `v1`
tracks the latest compatible major release. Before pushing or releasing, review and scan
the exact Git snapshot and release archive for secrets and private artifacts.

Licensed under [Apache 2.0](LICENSE).
