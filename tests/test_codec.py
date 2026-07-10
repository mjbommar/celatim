"""Codecs: symbol <-> field value round-trips exactly, for all three shapes."""

import pytest

from celatim.channel.codec import (
    Codec,
    FixedWidthCodec,
    SymbolChoiceCodec,
    VariableLengthCodec,
)


def test_codec_is_abstract():
    with pytest.raises(TypeError):
        Codec()  # type: ignore[abstract]


def test_fixed_width_capacity_and_roundtrip():
    c = FixedWidthCodec(4)
    assert c.capacity_bits == 4
    for symbol in range(16):
        assert c.decode_symbol(c.encode_symbol(symbol)) == symbol


def test_fixed_width_rejects_out_of_range_symbol():
    c = FixedWidthCodec(4)
    with pytest.raises(ValueError):
        c.encode_symbol(16)
    with pytest.raises(ValueError):
        c.encode_symbol(-1)


def test_fixed_width_rejects_nonpositive_width():
    with pytest.raises(ValueError):
        FixedWidthCodec(0)


def test_symbol_choice_capacity_is_floor_log2():
    assert SymbolChoiceCodec(16).capacity_bits == 4
    assert SymbolChoiceCodec(5).capacity_bits == 2  # floor(log2 5)
    assert SymbolChoiceCodec(2).capacity_bits == 1


def test_symbol_choice_roundtrip_and_metadata():
    c = SymbolChoiceCodec(16)
    assert c.num_symbols == 16
    for symbol in range(16):
        assert c.decode_symbol(c.encode_symbol(symbol)) == symbol


def test_symbol_choice_needs_two_symbols():
    with pytest.raises(ValueError):
        SymbolChoiceCodec(1)


def test_variable_length_capacity_and_roundtrip():
    c = VariableLengthCodec(3)
    assert c.capacity_bits == 24
    field = c.encode_symbol(0x010203)
    assert field == b"\x01\x02\x03"
    assert c.decode_symbol(field) == 0x010203


def test_variable_length_rejects_overwide_symbol():
    c = VariableLengthCodec(2)  # 16 bits
    with pytest.raises(ValueError):
        c.encode_symbol(1 << 16)


def test_variable_length_rejects_nonpositive_length():
    with pytest.raises(ValueError):
        VariableLengthCodec(0)
