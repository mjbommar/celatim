# Celatim 0.2.9

Celatim 0.2.9 closes the focused-study recall gaps by adding 44 field-level
covert-channel mechanisms drawn from the Lucena (IPv6), Hielscher (NTP), and
Velinov (QUIC) single-protocol studies.

## Catalog expansion

- The mechanism catalog grows from 146 to 190 rows (usable primary population
  133 to 176; five negative results).
- 43 new usable carriers plus one integrity-bound negative result: the NTP MAC
  message digest, whose keyed value is not freely settable.
- Full field-level coverage against the three focused studies rises to 22/22
  IPv6, 38/49 NTP, and 18/20 QUIC channels; the remaining non-full entries are
  partial matches of already-represented fields, not missing carriers.

## Modeling

- New rows apply the existing inclusion criterion; the `survivability` axis
  carries the path fragility of functional-field carriers
  (`path_dependent` / `nat_rewritten` where appropriate).
- The seven carrier classes still collapse onto the three codec shapes, so the
  new rows reuse the existing registry dispatch with no new codec code; every
  usable row round-trips a payload at its recorded evidence tier.
- The new rows are structural and codec-round-trip evidence. They do not carry
  cross-host execution claims; the executed campaign counts are unchanged.
