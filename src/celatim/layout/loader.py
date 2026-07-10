"""Authoritative header/field widths (in bits) measured from the system
``<netinet/*>`` struct definitions via the cmeasure C tool. Measurement only —
the tool performs no packet I/O; it reports ``sizeof``/``offsetof`` facts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

# layout/loader.py -> celatim -> src -> measurement/  (then measurement/cmeasure)
CMEASURE_DIR = Path(__file__).resolve().parents[3] / "cmeasure"


def build_c_tool(cmeasure_dir: Path = CMEASURE_DIR) -> Path:
    """Compile the header-facts tool (idempotent) and return the binary path."""
    subprocess.run(
        ["make", "-C", str(cmeasure_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    return cmeasure_dir / "header_facts"


def header_facts(cmeasure_dir: Path = CMEASURE_DIR) -> dict[str, int]:
    """Build (if needed), run the tool, and return its JSON facts as a dict."""
    binary = build_c_tool(cmeasure_dir)
    out = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)
