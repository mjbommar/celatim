UV ?= uv

.PHONY: sync lock-check format-check lint typecheck test qa package-smoke ci build

sync:
	$(UV) sync --locked --all-groups

lock-check:
	$(UV) lock --check

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

ci: sync qa package-smoke

build:
	$(UV) build --out-dir dist
