# Releasing Celatim

Celatim publishes from GitHub Actions with PyPI Trusted Publishing. No PyPI API
token or repository secret is used.

## Trusted publisher identity

Register this exact pending publisher at <https://pypi.org/manage/account/publishing/>:

- PyPI project name: `celatim`
- Owner: `mjbommar`
- Repository: `celatim`
- Workflow: `release.yml`
- Environment: `pypi`

The workflow filename and environment are OIDC identity claims. Changing either one
requires updating the publisher configuration on PyPI.

## One-time setup

1. Register the pending publisher above while signed in to PyPI.
2. Keep the GitHub `pypi` environment enabled. Add deployment protection rules when
   the repository plan supports them.
3. Select a software license, add its text as `LICENSE`, and declare its SPDX
   expression and license file in `pyproject.toml`.
4. Require the `CI / Python 3.14 quality and installed-package gate` check on `main`
   before making the repository public.

A pending publisher does not reserve the project name. The first successful trusted
publication creates the PyPI project and converts the pending publisher into a normal
publisher.

## Release procedure

1. Update `project.version` in `pyproject.toml` and refresh `uv.lock`.
2. Run `make ci` and `uv build --out-dir dist` locally.
3. Validate the distributions with `uvx twine check dist/*` and
   `uvx check-wheel-contents dist/*.whl`.
4. Commit and push the release changes.
5. Create a GitHub release whose tag is exactly `v<project.version>`.

Publishing the GitHub release triggers `.github/workflows/release.yml`. Its build job
runs without OIDC permission. Only the final publish job can request a short-lived PyPI
credential, and that job executes no repository code.
