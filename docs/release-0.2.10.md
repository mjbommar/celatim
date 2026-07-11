# Celatim 0.2.10

Celatim 0.2.10 improves the generated field-catalog appendix table.

## Report

- `report.tables` now emits the full-catalog longtable with a bold, shaded, repeating
  header row (`\rowcolor{cataloghead}`), zebra row striping (`\rowcolors{2}{catalogrow}
  {white}`), and increased row height for readability across the ~190-row catalog.
- The consuming document defines the `catalogrow` and `cataloghead` colors and loads
  `\usepackage[table]{xcolor}`. Column structure, data, and the density footnote are
  unchanged, so the table still tracks the single-source-of-truth catalog exactly.

No catalog, codec, measurement, or API changes.
