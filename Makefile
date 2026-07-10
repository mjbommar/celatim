UV ?= uv
UVX ?= uvx

.PHONY: sync lock-check security-audit format-check lint typecheck test qa package-smoke ci build

sync:
	$(UV) sync --locked --all-groups

lock-check:
	$(UV) lock --check

security-audit:
	@requirements="$$(mktemp)"; \
	trap 'rm -f "$$requirements"' EXIT; \
	$(UV) export --quiet --all-groups --all-extras --no-hashes --no-emit-project \
		--output-file "$$requirements"; \
	$(UVX) --from pip-audit==2.10.1 pip-audit \
		--requirement "$$requirements" --progress-spinner off --strict

format-check:
	$(UV) run ruff format --check .

lint:
	$(UV) run ruff check .

typecheck:
	$(UV) run ty check

test:
	$(UV) run pytest

qa: lock-check format-check lint typecheck test

package-smoke:
	$(UV) run python scripts/installed_wheel_smoke.py

ci: sync qa package-smoke security-audit

build:
	$(UV) build --out-dir dist
