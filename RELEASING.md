# Releasing

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes **one package per registry**, both named
`open-action-consent`:

| Registry | Install | Parts |
|---|---|---|
| PyPI | `pip install open-action-consent` | core; `[mcp]`, `[browser]`, `[approver]`, `[openai-agents]`, `[langgraph]`, `[all]` |
| npm | `npm install open-action-consent` | core; `open-action-consent/mcp`, `open-action-consent/vercel-ai` |

No password or token is stored anywhere. PyPI and npm trust this repository's `release.yml` directly ("trusted
publishing"), and npm adds a provenance statement linking the package to the commit that built it.

## One-time setup (maintainer)

### PyPI
1. Account at <https://pypi.org/account/register/> with two-factor authentication on.
2. <https://pypi.org/manage/account/publishing/> → GitHub → add one **pending publisher**: project `open-action-consent`,
   owner `Ishan2036924`, repository `open-action-consent`, workflow `release.yml`, environment `pypi`.

### npm
1. Account at <https://www.npmjs.com/signup> with two-factor authentication on. No organisation is needed.
2. npm shows a package's **Trusted Publisher** setting only once the package exists, so publish the first version by
   hand from `sdk/typescript` (you are asked to log in and for a two-factor code):

   ```
   cd sdk/typescript
   npm login
   npm ci --ignore-scripts
   npm run build
   npm publish --access public
   ```

3. On npmjs.com open `open-action-consent` → **Settings** → **Trusted Publisher** → **GitHub Actions**: organization or
   user `Ishan2036924`, repository `open-action-consent`, workflow filename `release.yml`, environment `npm`.

### GitHub (optional, recommended)
Repository **Settings → Environments**: give `pypi` and `npm` a required reviewer (the maintainer), so each publish waits
for an explicit approval click.

## Each release
1. Update the version in `sdk/python/pyproject.toml`, `sdk/typescript/package.json`, `oac.__version__` and `VERSION`
   in the TypeScript SDK; date the changelog section.
2. Push to `main` and wait for CI to pass.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
