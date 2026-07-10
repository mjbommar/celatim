"""Generate catalog-derived SVG figures for the paper.

The figures are deterministic and dependency-free so they can be regenerated in
the installed reviewer package without matplotlib, a browser, or LaTeX helpers.
They visualize structural catalog facts only; they do not make throughput or
production-path claims.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any
from xml.sax.saxutils import escape

from ..model import CarrierClass, Mechanism
from .protocol_rates import ProtocolRate, throughput_estimates

CAPACITY_BY_CLASS_FILENAME = "capacity-by-class.svg"
CLASS_LAYER_HEATMAP_FILENAME = "class-layer-heatmap.svg"
THROUGHPUT_UPPER_BOUNDS_FILENAME = "throughput-upper-bounds.svg"
LAYER_ORDER = ("link", "network", "transport", "session", "application", "control", "crypto")

_PALETTE = {
    CarrierClass.A: "#315f72",
    CarrierClass.B: "#5d8f69",
    CarrierClass.C: "#9b6b4f",
    CarrierClass.D: "#6d5f91",
    CarrierClass.E: "#b0823b",
    CarrierClass.F: "#3f7f91",
    CarrierClass.G: "#8a5369",
}


@dataclass(frozen=True)
class FigureArtifact:
    filename: str
    title: str
    content: str

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content.encode()).hexdigest()

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode())

    def to_json(self) -> dict[str, Any]:
        return {
            "filename": self.filename,
            "title": self.title,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True)
class ClassCapacitySummary:
    carrier_class: CarrierClass
    mechanism_count: int
    min_bits: int
    median_bits: float
    max_bits: int
    unbounded_count: int

    def to_json(self) -> dict[str, Any]:
        return {
            "carrier_class": self.carrier_class.value,
            "mechanism_count": self.mechanism_count,
            "min_bits": self.min_bits,
            "median_bits": self.median_bits,
            "max_bits": self.max_bits,
            "unbounded_count": self.unbounded_count,
        }


def capacity_by_class_data(mechanisms: Iterable[Mechanism]) -> tuple[ClassCapacitySummary, ...]:
    """Summarize representative raw capacity by carrier class for usable rows."""
    by_class: dict[CarrierClass, list[Mechanism]] = {
        carrier_class: [] for carrier_class in CarrierClass
    }
    for mechanism in mechanisms:
        if mechanism.is_usable_channel:
            by_class[mechanism.carrier_class].append(mechanism)
    rows: list[ClassCapacitySummary] = []
    for carrier_class in CarrierClass:
        class_mechanisms = by_class[carrier_class]
        bits = [mechanism.raw_capacity_bits for mechanism in class_mechanisms]
        rows.append(
            ClassCapacitySummary(
                carrier_class=carrier_class,
                mechanism_count=len(class_mechanisms),
                min_bits=min(bits) if bits else 0,
                median_bits=float(median(bits)) if bits else 0.0,
                max_bits=max(bits) if bits else 0,
                unbounded_count=sum(1 for mechanism in class_mechanisms if mechanism.unbounded),
            )
        )
    return tuple(rows)


def class_layer_count_data(
    mechanisms: Iterable[Mechanism],
) -> tuple[tuple[str, ...], tuple[tuple[CarrierClass, tuple[int, ...]], ...]]:
    """Return a carrier-class by protocol-layer count matrix for usable rows."""
    counts: Counter[tuple[CarrierClass, str]] = Counter()
    observed_layers: set[str] = set()
    for mechanism in mechanisms:
        if not mechanism.is_usable_channel:
            continue
        counts[(mechanism.carrier_class, mechanism.layer)] += 1
        observed_layers.add(mechanism.layer)
    layers = tuple(layer for layer in LAYER_ORDER if layer in observed_layers) + tuple(
        sorted(observed_layers - set(LAYER_ORDER))
    )
    matrix = tuple(
        (
            carrier_class,
            tuple(counts[(carrier_class, layer)] for layer in layers),
        )
        for carrier_class in CarrierClass
    )
    return layers, matrix


def capacity_by_class_svg(mechanisms: Iterable[Mechanism]) -> str:
    rows = capacity_by_class_data(mechanisms)
    width = 920
    height = 500
    left = 118
    right = 48
    top = 82
    bar_height = 30
    row_gap = 20
    chart_width = width - left - right
    max_log = max(math.log10(row.median_bits + 1.0) for row in rows) or 1.0
    body = [
        _text(28, 34, "Structural capacity by carrier class", size=22, weight="700"),
        _text(
            28,
            58,
            "Median representative bits per carrier unit, log10-scaled; counts include usable catalog rows only.",
            size=12,
            fill="#4a5568",
        ),
    ]
    for index, row in enumerate(rows):
        y = top + index * (bar_height + row_gap)
        log_value = math.log10(row.median_bits + 1.0)
        bar_width = 0 if row.mechanism_count == 0 else max(3.0, chart_width * log_value / max_log)
        label = f"Class {row.carrier_class.value}"
        if row.unbounded_count:
            bit_label = (
                f"median {row.median_bits:g} bits/unit; max {row.max_bits:g}+; "
                f"n={row.mechanism_count}; unbounded={row.unbounded_count}"
            )
        else:
            bit_label = (
                f"median {row.median_bits:g} bits/unit; max {row.max_bits:g}; "
                f"n={row.mechanism_count}"
            )
        body.extend(
            [
                _text(28, y + 21, label, size=13, weight="700", fill="#1a202c"),
                _rect(left, y, chart_width, bar_height, fill="#edf2f7"),
                _rect(left, y, bar_width, bar_height, fill=_PALETTE[row.carrier_class]),
                _text(left + 10, y + 20, bit_label, size=12, fill="#ffffff", weight="700")
                if bar_width > 330
                else _text(left + bar_width + 10, y + 20, bit_label, size=12, fill="#1a202c"),
            ]
        )
    body.extend(
        [
            _line(left, height - 58, width - right, height - 58, stroke="#a0aec0"),
            _text(left, height - 34, "0", size=11, fill="#4a5568"),
            _text(width - right - 82, height - 34, "higher median", size=11, fill="#4a5568"),
        ]
    )
    return _svg(width, height, "\n".join(body), "Structural capacity by carrier class")


def class_layer_heatmap_svg(mechanisms: Iterable[Mechanism]) -> str:
    layers, matrix = class_layer_count_data(mechanisms)
    cell_w = 92
    cell_h = 42
    left = 112
    top = 92
    width = left + len(layers) * cell_w + 42
    height = top + len(matrix) * cell_h + 92
    max_count = max((count for _, row in matrix for count in row), default=0)
    body = [
        _text(28, 34, "Mechanism count by class and layer", size=22, weight="700"),
        _text(
            28,
            58,
            "Counts include usable catalog rows; darker cells indicate more mechanisms.",
            size=12,
            fill="#4a5568",
        ),
    ]
    for col, layer in enumerate(layers):
        x = left + col * cell_w + cell_w / 2
        body.append(_text(x, top - 18, layer, size=11, anchor="middle", fill="#1a202c"))
    for row_index, (carrier_class, counts) in enumerate(matrix):
        y = top + row_index * cell_h
        body.append(
            _text(28, y + 26, f"Class {carrier_class.value}", size=13, weight="700", fill="#1a202c")
        )
        for col, count in enumerate(counts):
            x = left + col * cell_w
            fill = _heat_color(count, max_count)
            body.extend(
                [
                    _rect(x, y, cell_w - 4, cell_h - 4, fill=fill, stroke="#ffffff"),
                    _text(
                        x + (cell_w - 4) / 2,
                        y + 25,
                        str(count),
                        size=13,
                        weight="700",
                        anchor="middle",
                        fill="#1a202c" if count < max_count * 0.55 else "#ffffff",
                    ),
                ]
            )
    body.extend(
        [
            _text(left, height - 36, "0", size=11, fill="#4a5568"),
            _rect(left + 22, height - 49, 48, 16, fill=_heat_color(1, max_count)),
            _rect(left + 72, height - 49, 48, 16, fill=_heat_color(max_count, max_count)),
            _text(left + 130, height - 36, f"max cell = {max_count}", size=11, fill="#4a5568"),
        ]
    )
    return _svg(width, height, "\n".join(body), "Mechanism count by class and layer")


def throughput_upper_bounds_svg(
    mechanisms: Iterable[Mechanism],
    protocol_rates: Iterable[ProtocolRate],
) -> str:
    estimates = throughput_estimates(mechanisms, protocol_rates)
    width = 940
    row_height = 42
    top = 84
    left = 210
    right = 48
    height = top + max(1, len(estimates)) * row_height + 88
    chart_width = width - left - right
    max_log = max(
        (math.log10(estimate.structural_upper_bound_bps + 1.0) for estimate in estimates),
        default=1.0,
    )
    body = [
        _text(
            28,
            34,
            "Structural throughput upper bounds from rate assumptions",
            size=21,
            weight="700",
        ),
        _text(
            28,
            58,
            "Catalog bits/unit times cited carrier-unit rates; not measured production goodput.",
            size=12,
            fill="#4a5568",
        ),
    ]
    if not estimates:
        body.append(_text(28, top + 24, "No protocol-rate rows available.", size=13))
    for index, estimate in enumerate(estimates):
        y = top + index * row_height
        log_value = math.log10(estimate.structural_upper_bound_bps + 1.0)
        bar_width = max(3.0, chart_width * log_value / max_log)
        label = f"{estimate.mechanism_id} ({estimate.rate.unit_rate_hz:g} {estimate.rate.carrier_unit}/s)"
        value = f"{_format_bps(estimate.structural_upper_bound_bps)}; {estimate.claim_status}"
        body.extend(
            [
                _text(28, y + 24, label, size=12, weight="700", fill="#1a202c"),
                _rect(left, y, chart_width, 26, fill="#edf2f7"),
                _rect(left, y, bar_width, 26, fill="#5d8f69"),
                _text(left + bar_width + 10, y + 18, value, size=11, fill="#1a202c"),
            ]
        )
    body.extend(
        [
            _line(left, height - 50, width - right, height - 50, stroke="#a0aec0"),
            _text(left, height - 28, "0", size=11, fill="#4a5568"),
            _text(width - right - 112, height - 28, "higher upper bound", size=11, fill="#4a5568"),
        ]
    )
    return _svg(width, height, "\n".join(body), "Structural throughput upper bounds")


def catalog_figure_artifacts(
    mechanisms: Iterable[Mechanism],
    protocol_rates: Iterable[ProtocolRate] = (),
) -> tuple[FigureArtifact, ...]:
    mechs = tuple(mechanisms)
    rates = tuple(protocol_rates)
    artifacts = [
        FigureArtifact(
            filename=CAPACITY_BY_CLASS_FILENAME,
            title="Structural capacity by carrier class",
            content=capacity_by_class_svg(mechs),
        ),
        FigureArtifact(
            filename=CLASS_LAYER_HEATMAP_FILENAME,
            title="Mechanism count by class and layer",
            content=class_layer_heatmap_svg(mechs),
        ),
    ]
    if rates:
        artifacts.append(
            FigureArtifact(
                filename=THROUGHPUT_UPPER_BOUNDS_FILENAME,
                title="Structural throughput upper bounds",
                content=throughput_upper_bounds_svg(mechs, rates),
            )
        )
    return tuple(artifacts)


def write_catalog_figures(
    mechanisms: Iterable[Mechanism],
    output_dir: Path | str,
    protocol_rates: Iterable[ProtocolRate] = (),
) -> tuple[Path, ...]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for artifact in catalog_figure_artifacts(mechanisms, protocol_rates):
        path = output / artifact.filename
        path.write_text(artifact.content)
        paths.append(path)
    return tuple(paths)


def _format_bps(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.3g} Mbps"
    if value >= 1_000:
        return f"{value / 1_000:.3g} kbps"
    return f"{value:.3g} bps"


def _heat_color(count: int, max_count: int) -> str:
    if count <= 0 or max_count <= 0:
        return "#edf2f7"
    ratio = count / max_count
    return _blend("#dbeafe", "#315f72", ratio)


def _blend(start: str, end: str, ratio: float) -> str:
    ratio = max(0.0, min(1.0, ratio))
    s = _hex_to_rgb(start)
    e = _hex_to_rgb(end)
    return "#" + "".join(f"{round(s[i] + (e[i] - s[i]) * ratio):02x}" for i in range(3))


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    stripped = value.removeprefix("#")
    return (
        int(stripped[0:2], 16),
        int(stripped[2:4], 16),
        int(stripped[4:6], 16),
    )


def _svg(width: int, height: int, body: str, title: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title desc">\n'
        f'<title id="title">{escape(title)}</title>\n'
        '<desc id="desc">Generated from measurement/data/mechanisms.jsonl.</desc>\n'
        '<rect width="100%" height="100%" fill="#ffffff"/>\n'
        f"{body}\n"
        "</svg>\n"
    )


def _rect(
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    fill: str,
    stroke: str | None = None,
) -> str:
    stroke_attr = "" if stroke is None else f' stroke="{stroke}"'
    return (
        f'<rect x="{x:g}" y="{y:g}" width="{width:g}" height="{height:g}" '
        f'fill="{fill}"{stroke_attr}/>'
    )


def _line(x1: float, y1: float, x2: float, y2: float, *, stroke: str) -> str:
    return f'<line x1="{x1:g}" y1="{y1:g}" x2="{x2:g}" y2="{y2:g}" stroke="{stroke}"/>'


def _text(
    x: float,
    y: float,
    text: str,
    *,
    size: int,
    fill: str = "#1a202c",
    weight: str = "400",
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x:g}" y="{y:g}" font-family="Arial, Helvetica, sans-serif" '
        f'font-size="{size}" font-weight="{weight}" fill="{fill}" '
        f'text-anchor="{anchor}">{escape(text)}</text>'
    )


__all__ = [
    "CAPACITY_BY_CLASS_FILENAME",
    "CLASS_LAYER_HEATMAP_FILENAME",
    "LAYER_ORDER",
    "THROUGHPUT_UPPER_BOUNDS_FILENAME",
    "ClassCapacitySummary",
    "FigureArtifact",
    "capacity_by_class_data",
    "capacity_by_class_svg",
    "catalog_figure_artifacts",
    "class_layer_count_data",
    "class_layer_heatmap_svg",
    "throughput_upper_bounds_svg",
    "write_catalog_figures",
]
