# Releasing

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes **one package per registry**, both named
`open-action-consent`:

| Registry | Install | Parts |
|---|---|---|
| PyPI | `pip install open-action-consent` | core; `[mcp]`, `[browser]`, `[approver]`, `[openai-agents]`, `[langgraph]`, `[all]` |
| npm | `npm install open-action-consent` | core; `open-action-consent/mcp`, `open-action-consent/vercel-ai` |

No password or token is stored anywhere. PyPI and npm trust this repository's `release.yml` directly ("trusted
publishing"), and npm adds a provenance statement linking the package to the commit that built it. PyPI publishes at
once; npm only **stages** the version, and it goes live when a maintainer approves it.

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
   npm publish --access public --provenance=false
   ```

   (Provenance needs a CI system, so it is off for this one hand publish.)

3. On npmjs.com open `open-action-consent` → **Settings** → **Trusted Publisher** → **GitHub Actions**: organization or
   user `Ishan2036924`, repository `open-action-consent`, workflow filename `release.yml`, environment `npm`. Leave
   **Allow npm publish** and **Allow npm dist-tag** unticked: the workflow may only stage. Under **Publishing access**
   choose "Require two-factor authentication and disallow bypass 2fa tokens".

### GitHub (optional, recommended)
Repository **Settings → Environments**: give `pypi` and `npm` a required reviewer (the maintainer), so each publish waits
for an explicit approval click.

## Each release
1. Update the version in `sdk/python/pyproject.toml`, `sdk/typescript/package.json`, `oac.__version__` and `VERSION`
   in the TypeScript SDK; date the changelog section.
2. Push to `main` and wait for CI to pass.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. PyPI publishes by itself. For npm, open <https://www.npmjs.com/package/open-action-consent> → **Staged Packages**,
   check the version and files, and click **Approve** (two-factor login). Until then the version is not installable.
5. The workflow then makes the GitHub release page from the version's changelog section (`tools/release_notes.py`).
   CI fails while `sdk/python/pyproject.toml` names a version that has no dated section, so a missing one shows up
   before you tag. If the page step still fails, run its two commands from `release.yml` by hand.
6. The `sign` job then attaches the exact published files to the release page, each with a Sigstore bundle
   (`<file>.sigstore.json`), from `.github/workflows/sign-release.yml`. It downloads them from PyPI and npm and checks
   them against the registries' own digests first (`tools/fetch_published.py`); nothing is rebuilt. If npm was not
   approved yet, it signs the PyPI files and warns: after approving, open **Actions → sign-release → Run workflow**
   with the tag (for example `v0.5.1`). The same button backfills an older release.

## Checking a signed file

```
python -m pip install sigstore
python -m sigstore verify github --cert-identity \
  https://github.com/Ishan2036924/open-action-consent/.github/workflows/sign-release.yml@refs/tags/vX.Y.Z \
  open_action_consent-X.Y.Z-py3-none-any.whl
```

For a file signed by a hand run of sign-release, the identity ends in `@refs/heads/main` instead.

## CI dependencies

CI and the release build install Python packages only from hash-locked files in `ci/` (`pip install --require-hashes`),
and the SDK itself from a locally built wheel with `--no-deps`. Each `ci/*.in` names what a job needs; its `.txt` is the
lock, made with the command in the `.in` header (`uv pip compile --universal --python-version 3.10 --generate-hashes`,
so one file serves Python 3.10 to 3.13). Dependabot keeps them current. `tools/check_ci_locks.py` fails CI when a lock
lacks hashes, when a `.in` misses an SDK dependency or extra its job tests, or when a workflow installs anything else.
