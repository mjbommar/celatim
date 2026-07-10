"""Mechanism data-model invariants."""

import dataclasses

import pytest

from celatim.model import (
    CapacityModel,
    CarrierClass,
    DetectionAnnotationSource,
    DetectPredicate,
    FalsePositive,
    FieldLocator,
    FieldValueMatch,
    Mechanism,
    OnPathVisibility,
    Provenance,
    Reach,
    ScrubStrategy,
    Status,
    Survivability,
    WireBase,
)

BASE_MECHANISM = Mechanism(
    id="x",
    name="X",
    rfcs=("RFC 1",),
    protocol="P",
    layer="transport",
    carrier_class=CarrierClass.A,
    status=Status.NEW,
    carrier_unit="packet",
    raw_capacity_bits=4,
    header_bits=160,
    wire_bits_typical=12000,
    reach=Reach.UNWITTING,
    survivability=Survivability.END_TO_END,
    provenance=Provenance.SPEC,
    spec_quote="q",
)
RAW_CAPACITY_FIELD = "raw_capacity_bits"


def make(**over) -> Mechanism:
    return dataclasses.replace(BASE_MECHANISM, **over)


def test_constructs_and_is_frozen():
    m = make()
    assert m.carrier_class is CarrierClass.A
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(m, RAW_CAPACITY_FIELD, 9)  # frozen dataclass


def test_rejects_nonpositive_capacity():
    with pytest.raises(ValueError):
        make(raw_capacity_bits=0)


def test_rejects_wire_smaller_than_header():
    with pytest.raises(ValueError):
        make(header_bits=160, wire_bits_typical=8)


def test_c_field_provenance_requires_capacity_key():
    with pytest.raises(ValueError):
        make(provenance=Provenance.C_FIELD, c_capacity_key=None)


def test_c_header_provenance_requires_header_key():
    with pytest.raises(ValueError):
        make(provenance=Provenance.C_HEADER, c_header_key=None)


def test_capacity_model_follows_carrier_class():
    assert make(carrier_class=CarrierClass.A).capacity_model is CapacityModel.STORAGE
    assert make(carrier_class=CarrierClass.E).capacity_model is CapacityModel.STORAGE
    assert make(carrier_class=CarrierClass.F).capacity_model is CapacityModel.TIMING
    assert make(carrier_class=CarrierClass.G).capacity_model is CapacityModel.SUBLIMINAL


def test_effective_detection_annotations_preserve_explicit_catalog_values():
    m = make(
        detect_predicate=DetectPredicate.RESERVED_VALUE,
        false_positive=FalsePositive.BENIGN_NEVER,
    )

    assert m.effective_detect_predicate is DetectPredicate.RESERVED_VALUE
    assert m.effective_false_positive is FalsePositive.BENIGN_NEVER
    assert m.detection_annotation_source is DetectionAnnotationSource.EXPLICIT_CATALOG


def test_effective_detection_annotations_default_by_carrier_class():
    cases = {
        CarrierClass.A: (DetectPredicate.NONZERO, FalsePositive.BENIGN_RARE),
        CarrierClass.B: (DetectPredicate.ENTROPY, FalsePositive.BENIGN_COMMON),
        CarrierClass.C: (DetectPredicate.STATISTICAL, FalsePositive.BENIGN_COMMON),
        CarrierClass.D: (DetectPredicate.RESERVED_VALUE, FalsePositive.BENIGN_COMMON),
        CarrierClass.E: (DetectPredicate.PRESENCE, FalsePositive.BENIGN_COMMON),
        CarrierClass.F: (DetectPredicate.TIMING, FalsePositive.BENIGN_COMMON),
        CarrierClass.G: (DetectPredicate.NONE, FalsePositive.BENIGN_COMMON),
    }

    for carrier_class, (predicate, false_positive) in cases.items():
        m = make(carrier_class=carrier_class)
        assert m.effective_detect_predicate is predicate
        assert m.effective_false_positive is false_positive
        assert m.detection_annotation_source is DetectionAnnotationSource.DERIVED_DEFAULT


def test_field_value_match_masks_values():
    match = FieldValueMatch(value=0x0A0A0A0A, mask=0x0F0F0F0F)

    assert match.matches(0xFAFAFAFA)
    assert not match.matches(0x00000001)


def test_reserved_value_matches_require_reserved_predicate_and_locator():
    with pytest.raises(ValueError):
        make(
            detect_predicate=DetectPredicate.NONZERO,
            locator=FieldLocator(base=WireBase.NH, bit_offset=0, bit_width=8),
            reserved_value_matches=(FieldValueMatch(value=1),),
        )
    with pytest.raises(ValueError):
        make(
            detect_predicate=DetectPredicate.RESERVED_VALUE,
            reserved_value_matches=(FieldValueMatch(value=1),),
        )


def test_reserved_value_match_must_fit_locator_width():
    with pytest.raises(ValueError):
        make(
            detect_predicate=DetectPredicate.RESERVED_VALUE,
            locator=FieldLocator(base=WireBase.NH, bit_offset=0, bit_width=4),
            reserved_value_matches=(FieldValueMatch(value=0x10),),
        )


def test_valid_capacity_range():
    m = make(raw_capacity_bits=256, bits_min=160, bits_max=512)
    assert (m.bits_min, m.bits_max) == (160, 512)


def test_bits_min_cannot_exceed_typical():
    with pytest.raises(ValueError):
        make(raw_capacity_bits=4, bits_min=8)


def test_bits_max_cannot_be_below_typical():
    with pytest.raises(ValueError):
        make(raw_capacity_bits=8, bits_max=4)


def test_unbounded_forbids_finite_max():
    with pytest.raises(ValueError):
        make(unbounded=True, bits_max=1024)


def test_unbounded_without_max_is_ok():
    assert make(unbounded=True).unbounded is True


def test_survivability_is_independent_of_reach():
    # An integrity-bound field can still be cooperating-reach; the two axes are
    # distinct, so the model must let them vary independently.
    m = make(reach=Reach.COOPERATING, survivability=Survivability.INTEGRITY_BOUND)
    assert m.survivability is Survivability.INTEGRITY_BOUND
    assert m.reach is Reach.COOPERATING


def test_negative_result_defaults_usable():
    m = make()
    assert m.negative_result is False
    assert m.is_usable_channel is True


def test_negative_result_marks_non_channel():
    # §7 contrast case: a field that exists but is validated/signed, so not a channel.
    m = make(negative_result=True)
    assert m.is_usable_channel is False


def test_robust_unwitting_predicate():
    assert (
        make(reach=Reach.UNWITTING, survivability=Survivability.END_TO_END).robust_unwitting is True
    )
    # scrubbed away in-path -> not robust
    assert (
        make(reach=Reach.UNWITTING, survivability=Survivability.NORMALIZED).robust_unwitting
        is False
    )
    # endpoint-only -> not an unwitting threat
    assert (
        make(reach=Reach.COOPERATING, survivability=Survivability.END_TO_END).robust_unwitting
        is False
    )


def test_scrub_strategy_follows_class_for_storage():
    end = Survivability.END_TO_END
    cases = {
        CarrierClass.A: ScrubStrategy.CANONICALIZE_ZERO,
        CarrierClass.B: ScrubStrategy.REPLACE_PADDING,
        CarrierClass.C: ScrubStrategy.REWRITE_FIELD,
        CarrierClass.D: ScrubStrategy.BLOCK_CODEPOINT,
        CarrierClass.E: ScrubStrategy.STRIP_ELEMENT,
    }
    for cls, strat in cases.items():
        assert make(carrier_class=cls, survivability=end).scrub_strategy is strat


def test_integrity_bound_moves_scrub_to_endpoint():
    # A storage field under a crypto integrity check can't be rewritten in-path.
    m = make(carrier_class=CarrierClass.C, survivability=Survivability.INTEGRITY_BOUND)
    assert m.scrub_strategy is ScrubStrategy.ENDPOINT_ONLY


def test_integrity_and_confidentiality_are_independent_detection_axes():
    clear = make(
        carrier_class=CarrierClass.A,
        survivability=Survivability.INTEGRITY_BOUND,
        on_path_visibility=OnPathVisibility.CLEARTEXT,
    )
    encrypted = dataclasses.replace(clear, on_path_visibility=OnPathVisibility.ENCRYPTED)
    conditional = dataclasses.replace(
        clear, on_path_visibility=OnPathVisibility.DEPLOYMENT_DEPENDENT
    )

    assert clear.detectability.value == "stateful_dpi"
    assert encrypted.detectability.value == "endpoint_only"
    assert conditional.detectability.value == "visibility_dependent"
    assert clear.scrub_strategy is encrypted.scrub_strategy is ScrubStrategy.ENDPOINT_ONLY


def test_timing_and_subliminal_scrub_ignore_survivability():
    # Shaping works even under AEAD; the subliminal channel is a design-time fix.
    f = make(carrier_class=CarrierClass.F, survivability=Survivability.INTEGRITY_BOUND)
    g = make(carrier_class=CarrierClass.G, survivability=Survivability.INTEGRITY_BOUND)
    assert f.scrub_strategy is ScrubStrategy.SHAPE_TIMING
    assert g.scrub_strategy is ScrubStrategy.ENFORCE_DETERMINISTIC
