"""Core data model: one Mechanism == one row of the survey catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CarrierClass(str, Enum):
    A = "A"  # reserved / MBZ bits ("ignored on receipt")
    B = "B"  # padding (alignment / TFC / record)
    C = "C"  # opaque / arbitrary-value fields
    D = "D"  # reserved codepoints (GREASE-style)
    E = "E"  # optional / unrecognized-but-forwarded
    F = "F"  # timing / count channels
    G = "G"  # subliminal channels in cryptographic primitives


class CapacityModel(str, Enum):
    """How a mechanism's capacity is quantified — determined by ``carrier_class``.

    The storage classes (A–E) pack covert bits into a field, so a width-based
    density (bits per header / per PDU) is the right measure. Class F is a
    *timing/count* channel with no field content: its capacity is rate-modeled
    (Anantharam & Verdú, "Bits through queues", 1996 — a single-server queue
    timing channel carries ~mu/e nats/s), not a field width. Class G is a
    *subliminal* channel whose capacity is bounded by the entropy of a crypto
    field (Simmons: broadband ~= all signature bits not spent on forgery
    resistance, narrowband far fewer). Metrics dispatch on this discriminator
    so width-based density is never (mis)applied to F/G rows."""

    STORAGE = "storage"
    TIMING = "timing"
    SUBLIMINAL = "subliminal"


class Status(str, Enum):
    DOC = "DOC"  # already documented in the prior wiki
    EXT = "EXT"  # extends an existing wiki page
    NEW = "NEW"  # new to this survey


class Provenance(str, Enum):
    C_FIELD = "c_field"  # capacity width measured directly from a C struct field
    C_HEADER = "c_header"  # header-size denominator from C; capacity is spec-sourced
    SPEC = "spec"  # all values taken from the RFC text


class Reach(str, Enum):
    UNWITTING = "unwitting"  # works against an unmodified receiver
    COOPERATING = "cooperating"  # needs a colluding endpoint / observer
    MULTIHOP = "multihop"  # propagates across forwarding hops


class Survivability(str, Enum):
    """Whether the covert bits cross a typical Internet path intact — a distinct
    axis from ``reach`` (who can receive). The genuinely dangerous mechanisms sit
    at ``UNWITTING`` reach AND ``END_TO_END`` survivability. Grounded in middlebox
    measurement: Honda et al. (IMC 2011) — middleboxes rewrite the ISN and strip
    undefined TCP options; Detal et al. tracebox (IMC 2013) — observed in-path
    rewrites of TTL/DSCP/MSS; Handley, Kreibich & Paxson (USENIX Sec 2001) — the
    traffic normalizer scrubs reserved/MBZ bits to zero."""

    END_TO_END = "end_to_end"  # typically forwarded unchanged (opaque/optional/payload)
    NAT_REWRITTEN = "nat_rewritten"  # commonly altered by NAPT (addresses, ports, ISN, IP ID)
    NORMALIZED = "normalized"  # commonly zeroed by scrubbers/firewalls (reserved/MBZ bits, DSCP)
    INTEGRITY_BOUND = (
        "integrity_bound"  # under a crypto integrity check: intact end-to-end but only
    )
    #                                      between cooperating endpoints; cannot be scrubbed in-path
    #                                      without breaking authentication (cf. §7 negative results)


class OnPathVisibility(str, Enum):
    """Whether an ordinary in-path observer can read the carrier field itself.

    This is independent of integrity. A cleartext authenticated field can be observed
    but not transparently rewritten, while an encrypted field requires endpoint keys.
    Some application protocols can run in either mode and must remain conditional.
    """

    CLEARTEXT = "cleartext"
    ENCRYPTED = "encrypted"
    DEPLOYMENT_DEPENDENT = "deployment_dependent"


class ScrubStrategy(str, Enum):
    """The conformant defense that neutralizes a mechanism — derived from
    ``carrier_class`` and ``survivability`` (see ``Mechanism.scrub_strategy``).
    This operationalizes the survey's detect-and-scrub mandate: you defend by
    carrier class, not field by field."""

    CANONICALIZE_ZERO = (
        "canonicalize_zero"  # reset reserved/MBZ bits to 0 (A); cf. Handley normalizer
    )
    REPLACE_PADDING = "replace_padding"  # overwrite / re-pad padding content (B)
    REWRITE_FIELD = "rewrite_field"  # re-randomize the opaque field (C); what NAT does to IP ID/ISN
    BLOCK_CODEPOINT = "block_codepoint"  # reject reserved / GREASE codepoints (D)
    STRIP_ELEMENT = "strip_element"  # drop the optional / unrecognized element (E)
    SHAPE_TIMING = "shape_timing"  # jitter / normalize inter-arrival & counts (F); works under AEAD
    ENFORCE_DETERMINISTIC = (
        "enforce_deterministic"  # design-time: deterministic nonces (RFC 6979) / 0-len salt (G)
    )
    ENDPOINT_ONLY = (
        "endpoint_only"  # integrity-bound: in-path rewrite breaks auth; fix at the endpoint
    )


class WireBase(str, Enum):
    """Header anchor for a wire-format field offset. Mirrors nftables' raw-payload
    bases so a locator emits directly as ``@<base>,<offset>,<len>``."""

    LL = "ll"  # link layer (Ethernet)
    NH = "nh"  # network header (IPv4 / IPv6)
    TH = "th"  # transport header (TCP / UDP)


class DetectPredicate(str, Enum):
    """What observation flags a mechanism's misuse. The first three are
    stateless-expressible (fixed offset + mask compare); the rest need flow
    state, entropy, baselining, or are not observable on the wire at all."""

    NONZERO = "nonzero"  # MBZ field must be 0; alert if != 0 (Class A)
    RESERVED_VALUE = "reserved_value"  # value drawn from a reserved/GREASE set (Class D)
    CONDITIONAL = "conditional"  # field meaningful only under a guard flag (e.g. URG ptr)
    ENTROPY = "entropy"  # padding/opaque content randomness (Class B) — stateful
    PRESENCE = "presence"  # optional/unknown element present (Class E) — stateful
    STATISTICAL = "statistical"  # arbitrary value is legal; needs a baseline (Class C / IP ID)
    TIMING = "timing"  # inter-arrival / count (Class F) — offline statistical
    NONE = "none"  # not observable on the wire (Class G subliminal)


class FalsePositive(str, Enum):
    """Benign base rate — the alert-vs-log dial. The survey's 'worth further
    research' framing: only ``BENIGN_NEVER``/``RARE`` should fire an alert;
    ``BENIGN_COMMON`` (GREASE, padding, spin-bit randomization) is log-for-baseline."""

    BENIGN_NEVER = "benign_never"  # no legitimate use; any occurrence is suspicious
    BENIGN_RARE = "benign_rare"  # legitimate but uncommon; low-FP alert
    BENIGN_COMMON = "benign_common"  # legitimately frequent; log/baseline, do not alert


class DetectionAnnotationSource(str, Enum):
    """Whether detector posture is authored in the catalog or class-derived.

    The explicit catalog fields are still the source of truth for precise rule
    emission. Derived defaults keep public guidance complete while the full
    locator/predicate/false-positive migration is in progress."""

    EXPLICIT_CATALOG = "explicit_catalog"
    DERIVED_DEFAULT = "derived_default"


class Detectability(str, Enum):
    """Where (if anywhere) the mechanism is observable — derived from
    ``capacity_model`` + ``on_path_visibility`` + ``detect_predicate``. Timing is
    observable even under encryption (arrival times leak). Integrity and
    confidentiality are separate: a cleartext authenticated field remains observable,
    while an encrypted field requires endpoint keys."""

    STATELESS_FILTER = "stateless_filter"  # fixed offset+mask: nftables/iptables/BPF
    STATEFUL_DPI = "stateful_dpi"  # needs flow state / parsing / entropy: Zeek/Suricata
    STATISTICAL = "statistical"  # baseline / timing analysis, offline
    ENDPOINT_ONLY = "endpoint_only"  # protocol-encrypted; endpoint keys reveal the field
    VISIBILITY_DEPENDENT = (
        "visibility_dependent"  # cleartext or encrypted depending on deployment/mode
    )
    UNDETECTABLE_ONWIRE = (
        "undetectable_onwire"  # subliminal: indistinguishable from required randomness
    )


@dataclass(frozen=True)
class FieldLocator:
    """Wire-format position of a field, MSB-first from a header base. Authored
    from the RFC packet diagram (the authoritative wire layout) and cross-checked
    against Scapy at test time. This is the nftables raw-payload model verbatim,
    so it emits to nft/iptables/BPF without translation."""

    base: WireBase
    bit_offset: int  # MSB-first offset from the start of `base`'s header
    bit_width: int

    def __post_init__(self) -> None:
        if self.bit_offset < 0:
            raise ValueError("bit_offset must be >= 0")
        if self.bit_width <= 0:
            raise ValueError("bit_width must be positive")

    @property
    def spans_single_byte(self) -> bool:
        return self.bit_offset // 8 == (self.bit_offset + self.bit_width - 1) // 8

    @property
    def byte_offset(self) -> int:
        return self.bit_offset // 8

    @property
    def byte_mask(self) -> int:
        """AND-mask within the containing byte (single-byte fields only) — the
        value BPF/iptables-u32 compare against."""
        if not self.spans_single_byte:
            raise ValueError("byte_mask is defined only for single-byte-spanning fields")
        shift = 8 - (self.bit_offset % 8) - self.bit_width
        return ((1 << self.bit_width) - 1) << shift


@dataclass(frozen=True)
class FieldValueMatch:
    """A concrete value predicate for a located field.

    ``mask`` is optional. When present, the detector matches
    ``field_value & mask == value``; when absent, it matches exact equality.
    This is needed for sparse reserved-codepoint families such as QUIC's
    0x?a?a?a?a version pattern.
    """

    value: int
    mask: int | None = None

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ValueError("value must be >= 0")
        if self.mask is not None:
            if self.mask < 0:
                raise ValueError("mask must be >= 0")
            if self.value & ~self.mask:
                raise ValueError("masked value must not set bits outside mask")

    def matches(self, field_value: int) -> bool:
        if self.mask is None:
            return field_value == self.value
        return field_value & self.mask == self.value


@dataclass(frozen=True)
class Mechanism:
    id: str
    name: str
    rfcs: tuple[str, ...]
    protocol: str
    layer: str
    carrier_class: CarrierClass
    status: Status
    carrier_unit: str
    raw_capacity_bits: int  # representative (typical) covert bits per carrier unit
    header_bits: int  # this protocol's header size (density_header denominator)
    wire_bits_typical: int  # typical full on-wire PDU size (density_wire denominator)
    reach: Reach  # who can receive: unwitting / cooperating / multihop
    survivability: Survivability  # whether the bits cross the path intact (middlebox hazard)
    provenance: Provenance
    spec_quote: str
    c_capacity_key: str | None = None  # cmeasure key cross-checking the field width
    c_header_key: str | None = None  # cmeasure key cross-checking the header size
    bits_min: int | None = None  # lower end of a capacity range (None => point value)
    bits_max: int | None = None  # upper end of a finite range (None => point value, or unbounded)
    unbounded: bool = False  # True => no finite per-unit ceiling (whole-frame/stream carriers)
    locator: FieldLocator | None = None  # wire position, for rule emission (None => not located)
    detect_predicate: DetectPredicate | None = (
        None  # what observation flags misuse (None => unassessed)
    )
    false_positive: FalsePositive | None = None  # benign base rate: alert-vs-log dial
    on_path_visibility: OnPathVisibility = OnPathVisibility.CLEARTEXT
    reserved_value_matches: tuple[FieldValueMatch, ...] = ()
    negative_result: bool = False  # §7 contrast case: field exists but is NOT a usable
    #                                channel (validated / signed / header-protected against
    #                                the relevant adversary). Kept for completeness, not capacity.

    @property
    def effective_detect_predicate(self) -> DetectPredicate:
        """Detector posture used in generated guidance.

        ``detect_predicate`` remains the explicit catalog field used for precise
        stateless rule eligibility. This derived value fills the reviewer-facing
        guidance table by carrier class without implying an exact locator exists."""
        if self.detect_predicate is not None:
            return self.detect_predicate
        return {
            CarrierClass.A: DetectPredicate.NONZERO,
            CarrierClass.B: DetectPredicate.ENTROPY,
            CarrierClass.C: DetectPredicate.STATISTICAL,
            CarrierClass.D: DetectPredicate.RESERVED_VALUE,
            CarrierClass.E: DetectPredicate.PRESENCE,
            CarrierClass.F: DetectPredicate.TIMING,
            CarrierClass.G: DetectPredicate.NONE,
        }[self.carrier_class]

    @property
    def effective_false_positive(self) -> FalsePositive:
        """False-positive posture used in generated guidance.

        Class defaults are conservative: fields that are routinely variable,
        optional, GREASE-like, timing-shaped, or cryptographic stay log/baseline
        first, while reserved/MBZ bit misuse defaults to rare enough to alert
        once a real detector has been validated."""
        if self.false_positive is not None:
            return self.false_positive
        return {
            CarrierClass.A: FalsePositive.BENIGN_RARE,
            CarrierClass.B: FalsePositive.BENIGN_COMMON,
            CarrierClass.C: FalsePositive.BENIGN_COMMON,
            CarrierClass.D: FalsePositive.BENIGN_COMMON,
            CarrierClass.E: FalsePositive.BENIGN_COMMON,
            CarrierClass.F: FalsePositive.BENIGN_COMMON,
            CarrierClass.G: FalsePositive.BENIGN_COMMON,
        }[self.carrier_class]

    @property
    def detection_annotation_source(self) -> DetectionAnnotationSource:
        """Source marker for effective detector posture.

        If either posture field is absent, generated guidance is partly
        class-derived and must not be read as fully authored catalog metadata."""
        if self.detect_predicate is not None and self.false_positive is not None:
            return DetectionAnnotationSource.EXPLICIT_CATALOG
        return DetectionAnnotationSource.DERIVED_DEFAULT

    @property
    def is_usable_channel(self) -> bool:
        """False for documented non-channels (catalog §7): the field is present but
        validated or integrity-protected, so it cannot carry covert data to the
        relevant receiver. Catalogued as contrast cases, excluded from capacity."""
        return not self.negative_result

    @property
    def capacity_model(self) -> CapacityModel:
        """Storage for A–E, timing for F, subliminal for G. Capacity is
        quantified differently per family, so the metrics layer dispatches on
        this rather than blindly applying width-based density to every row."""
        if self.carrier_class is CarrierClass.F:
            return CapacityModel.TIMING
        if self.carrier_class is CarrierClass.G:
            return CapacityModel.SUBLIMINAL
        return CapacityModel.STORAGE

    @property
    def robust_unwitting(self) -> bool:
        """The high-threat predicate: usable against an unmodified receiver
        (unwitting) AND surviving a typical path intact (end-to-end). The cross
        of these two axes is the survey's headline filter — most reserved-bit
        channels fail one or the other (scrubbed, NAT-rewritten, or endpoint-only)."""
        return self.reach is Reach.UNWITTING and self.survivability is Survivability.END_TO_END

    @property
    def scrub_strategy(self) -> ScrubStrategy:
        """The conformant defense, derived structurally. Timing channels (F) are
        beaten by shaping — which works even when the payload is encrypted — and
        G's signature-randomness channel is closed only at design time
        (deterministic nonces, RFC 6979). For the storage classes (A–E), a field
        carried under a crypto integrity check cannot be rewritten in-path
        without breaking authentication, so its defense moves to the endpoint;
        otherwise the strategy follows the carrier class."""
        if self.carrier_class is CarrierClass.F:
            return ScrubStrategy.SHAPE_TIMING
        if self.carrier_class is CarrierClass.G:
            return ScrubStrategy.ENFORCE_DETERMINISTIC
        if self.survivability is Survivability.INTEGRITY_BOUND:
            return ScrubStrategy.ENDPOINT_ONLY
        return {
            CarrierClass.A: ScrubStrategy.CANONICALIZE_ZERO,
            CarrierClass.B: ScrubStrategy.REPLACE_PADDING,
            CarrierClass.C: ScrubStrategy.REWRITE_FIELD,
            CarrierClass.D: ScrubStrategy.BLOCK_CODEPOINT,
            CarrierClass.E: ScrubStrategy.STRIP_ELEMENT,
        }[self.carrier_class]

    @property
    def detectability(self) -> Detectability:
        """Where the mechanism is observable, independently of rewrite safety."""
        if self.capacity_model is CapacityModel.SUBLIMINAL:
            return Detectability.UNDETECTABLE_ONWIRE
        if self.capacity_model is CapacityModel.TIMING:
            return Detectability.STATISTICAL
        if self.on_path_visibility is OnPathVisibility.ENCRYPTED:
            return Detectability.ENDPOINT_ONLY
        if self.on_path_visibility is OnPathVisibility.DEPLOYMENT_DEPENDENT:
            return Detectability.VISIBILITY_DEPENDENT
        if self.survivability is Survivability.INTEGRITY_BOUND:
            # The field is observable but authenticated. Keep it out of automatic
            # fixed-offset rule emission until the enclosing authenticated protocol is
            # parsed; integrity constrains rewriting, not inspection.
            return Detectability.STATEFUL_DPI
        stateless = {
            DetectPredicate.NONZERO,
            DetectPredicate.RESERVED_VALUE,
            DetectPredicate.CONDITIONAL,
        }
        if self.locator is not None and self.detect_predicate in stateless:
            return Detectability.STATELESS_FILTER
        if self.detect_predicate in {DetectPredicate.STATISTICAL, DetectPredicate.TIMING}:
            return Detectability.STATISTICAL
        return Detectability.STATEFUL_DPI

    def __post_init__(self) -> None:
        if self.raw_capacity_bits <= 0:
            raise ValueError(f"{self.id}: raw_capacity_bits must be positive")
        if self.header_bits <= 0:
            raise ValueError(f"{self.id}: header_bits must be positive")
        if self.wire_bits_typical < self.header_bits:
            raise ValueError(f"{self.id}: wire_bits_typical must be >= header_bits")
        if self.provenance is Provenance.C_FIELD and not self.c_capacity_key:
            raise ValueError(f"{self.id}: C_FIELD provenance requires c_capacity_key")
        if self.provenance is Provenance.C_HEADER and not self.c_header_key:
            raise ValueError(f"{self.id}: C_HEADER provenance requires c_header_key")
        # raw_capacity_bits is the representative point estimate; bits_min/bits_max
        # bracket it when the spec gives a range, and `unbounded` flags carriers
        # with no finite per-unit ceiling (so they are excluded from finite-max
        # statistics rather than masquerading as a precise number).
        if self.bits_min is not None and not 0 < self.bits_min <= self.raw_capacity_bits:
            raise ValueError(f"{self.id}: bits_min must satisfy 0 < bits_min <= raw_capacity_bits")
        if self.bits_max is not None and self.bits_max < self.raw_capacity_bits:
            raise ValueError(f"{self.id}: bits_max must be >= raw_capacity_bits")
        if self.unbounded and self.bits_max is not None:
            raise ValueError(f"{self.id}: unbounded mechanisms must not set a finite bits_max")
        if self.reserved_value_matches:
            if self.detect_predicate is not DetectPredicate.RESERVED_VALUE:
                raise ValueError(
                    f"{self.id}: reserved_value_matches require detect_predicate=reserved_value"
                )
            if self.locator is None:
                raise ValueError(f"{self.id}: reserved_value_matches require a field locator")
            field_limit = 1 << self.locator.bit_width
            for match in self.reserved_value_matches:
                if match.value >= field_limit:
                    raise ValueError(f"{self.id}: reserved value exceeds locator width")
                if match.mask is not None and match.mask >= field_limit:
                    raise ValueError(f"{self.id}: reserved mask exceeds locator width")
