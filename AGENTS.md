# Celatim

Celatim is the Python 3.14+ package for the RFC covert-channel survey and measurement
artifact. The distribution, import namespace, and primary console command are all
named `celatim`.

## Engineering requirements

- Keep one PEP 621 project, one lockfile, and one import namespace.
- Preserve the typed public API and `py.typed` marker.
- Keep optional protocol stacks lazy and isolated behind extras.
- Run `make ci` before release-facing changes. The installed-wheel smoke must execute
  outside the checkout and without repository imports.
- Use `uv lock --check`, Ruff formatting and lint, `ty check`, and pytest as mandatory
  gates.
- Do not add PyPI tokens or passwords. Publishing uses the `pypi` GitHub environment
  and `.github/workflows/release.yml` through OIDC.
- Do not weaken the release workflow's version, license, metadata, archive, or installed
  package checks.

Run channel implementations only in controlled, authorized environments. Source code
is part of the public reproducibility artifact; secrets, sensitive payloads, and private
run transcripts are not.
