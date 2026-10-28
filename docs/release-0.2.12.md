# Celatim 0.2.12

Celatim 0.2.12 raises audited dependency floors and fixes the field-catalog appendix
table width.

## Dependencies

- The `transfer` and `crypto` extras now require `cryptography>=50.0.0`.
- The `daemon` extra now requires `h2>=4.4.1`.
- The `dns` extra now requires `dnspython>=2.9.0` (CVE-2026-114605).
- The lockfile picks up `certifi` 2026.10.19, which tracks Mozilla's root store.

## Report

- `report.tables` narrows the field-catalog Mechanism column to `0.435\textwidth` so
  the longtable stays inside the text block instead of overrunning the right margin.

## Documentation

- The `channel.registry` module docstring now states the correct catalog mechanism count.

No catalog, codec, measurement, or API changes.
