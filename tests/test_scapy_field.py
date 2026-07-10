"""Named-field Scapy carriers (rigorous placement in the real protocol field)."""

from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from celatim.pdu import scapy_field


def test_supports_registered_rows():
    assert scapy_field.supports("mpls-exp-tc")
    assert not scapy_field.supports("tcp-reserved-bits")


def test_mpls_cos_roundtrips_in_real_pdu():
    for value in range(8):  # 3-bit EXP/TC field
        carrier = scapy_field.build_field_pdu("mpls-exp-tc", value)
        assert len(carrier) > 4  # a real MPLS label entry + IP payload, not a blob
        assert scapy_field.extract_field_value("mpls-exp-tc", carrier) == value


def test_value_out_of_range_raises():
    with pytest.raises(ValueError, match="does not fit"):
        scapy_field.build_field_pdu("mpls-exp-tc", 8)
