# Releasing

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which builds and publishes:

| Registry | Packages |
|---|---|
| PyPI | `open-action-consent`, `oac-mcp`, `oac-gated-browser`, `oac-approver`, `oac-openai-agents`, `oac-langgraph` |
| npm | `@open-action-consent/sdk`, `@open-action-consent/mcp`, `@open-action-consent/vercel-ai` |

No password or token is stored anywhere. PyPI and npm trust this repository's `release.yml` directly ("trusted
publishing"), and npm adds a provenance statement linking each package to the commit that built it.

## One-time setup (maintainer)

### PyPI

1. Create an account at <https://pypi.org/account/register/> and turn on two-factor authentication.
2. Open <https://pypi.org/manage/account/publishing/>, choose **GitHub**, and add a **pending publisher** six times,
   once per project name below, each with the same four values:

   | Field | Value |
   |---|---|
   | PyPI Project Name | `open-action-consent` (then `oac-mcp`, `oac-gated-browser`, `oac-approver`, `oac-openai-agents`, `oac-langgraph`) |
   | Owner | `Ishan2036924` |
   | Repository name | `open-action-consent` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

### npm

1. Create an account at <https://www.npmjs.com/signup> and turn on two-factor authentication.
2. Create the free organisation `open-action-consent` at <https://www.npmjs.com/org/create>.
3. For each package (`@open-action-consent/sdk`, `@open-action-consent/mcp`, `@open-action-consent/vercel-ai`) open
   its **Settings** on npmjs.com, **Trusted Publisher** > **GitHub Actions**, and enter:

   | Field | Value |
   |---|---|
   | Organization or user | `Ishan2036924` |
   | Repository | `open-action-consent` |
   | Workflow filename | `release.yml` |
   | Environment name | `npm` |

   If npm only shows these settings once a package exists, publish the first version by hand from the repository
   root (you are asked to log in), then add the trusted publisher; the release workflow skips versions already on
   npm:

   ```
   npm login
   npm ci --ignore-scripts
   npm run build --workspaces
   npm publish --workspace sdk/typescript --access public
   npm publish --workspace integrations/mcp-typescript --access public
   npm publish --workspace integrations/vercel-ai --access public
   ```

## Each release

1. Update the versions (all `pyproject.toml` and `package.json` files, `oac.__version__`, `VERSION` in the TS SDK)
   and move the changelog's top section from "unreleased" to the date.
2. Push to `main` and wait for CI to pass.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
