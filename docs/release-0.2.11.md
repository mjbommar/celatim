# Celatim 0.2.11

Celatim 0.2.11 tightens the generated field-catalog appendix table.

## Report

- `report.tables` now renders the RFC column without the redundant `RFC ` prefix
  (the column is already labeled `RFC(s)`), so multi-RFC cells such as `9768, 9293, 793`
  read cleanly and no longer wrap.
- Column widths rebalance to match: the Mechanism column widens to `0.46\textwidth` and
  the RFC(s) column narrows to `0.10\textwidth`.

No catalog, codec, measurement, or API changes.
