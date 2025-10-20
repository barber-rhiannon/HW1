'''
Author: Rhiannon Barber
Date: Oct. 20, 2025
CS454: Homework 1 - DES project

Unit tests:
- test_hex_roundtrip_and_padding: verifies hex→bits→hex roundtrip and zero-padding to 64 bits
- test_hex_to_binary_invalid_input_raises: ensures non-hex input raises ValueError
- test_apply_permutation_identity: identity permutation returns the same bits
- test_apply_permutation_out_of_range_index_raises: bad index raises IndexError
- test_circular_left_shift_wraparound: left shifts wrap and modulo length is respected
- test_generate_subkeys_shapes_and_bit_content: C/D/K sizes and bit content
- test_feistel_output_is_32_bits: f-function always returns 32 bits of 0/1
- test_end_to_end_fips_encrypt: FIPS vector encrypts to expected ciphertext
- test_end_to_end_fips_decrypt: FIPS vector decrypts to original plaintext
- test_roundtrip_randomized_blocks_and_keys: N random cases encrypt→decrypt roundtrip
- test_roundtrip_edge_patterns: edge pattern blocks and keys roundtrip correctly
'''

import importlib
import os
import random
import string
import pytest

DES = importlib.import_module("DES")


def test_hex_roundtrip_and_padding():
    hex_in = "0123456789ABCDEF"
    bits = DES.hex_to_binary(hex_in, 64)
    assert isinstance(bits, str)
    assert len(bits) == 64
    assert set(bits) <= {"0", "1"}
    hex_out = DES.binary_to_hex(bits)
    assert hex_out == hex_in


def test_hex_to_binary_invalid_input_raises():
    with pytest.raises(ValueError):
        DES.hex_to_binary("G123", 64)
    with pytest.raises(ValueError):
        DES.hex_to_binary("XYZ", 64)
    with pytest.raises(ValueError):
        DES.hex_to_binary("", 64)


def test_apply_permutation_identity():
    bits = "10110011"
    identity = list(range(1, 9))
    assert DES.apply_permutation(bits, identity) == bits


def test_apply_permutation_out_of_range_index_raises():
    bits = "1011"
    bad = [1, 2, 3, 5]
    with pytest.raises(IndexError):
        DES.apply_permutation(bits, bad)


def test_circular_left_shift_wraparound():
    assert DES.circular_left_shift("abcd", 0) == "abcd"
    assert DES.circular_left_shift("abcd", 1) == "bcda"
    assert DES.circular_left_shift("abcd", 2) == "cdab"
    assert DES.circular_left_shift("abcd", 4) == "abcd"
    assert DES.circular_left_shift("abcd", 6) == "cdab"


def test_generate_subkeys_shapes_and_bit_content():
    key_hex = "133457799BBCDFF1"
    Cs, Ds, Ks = DES.generate_subkeys(key_hex)
    assert len(Cs) == 17
    assert len(Ds) == 17
    assert len(Ks) == 16
    for c in Cs:
        assert len(c) == 28 and set(c) <= {"0", "1"}
    for d in Ds:
        assert len(d) == 28 and set(d) <= {"0", "1"}
    for k in Ks:
        assert len(k) == 48 and set(k) <= {"0", "1"}


def test_feistel_output_is_32_bits():
    r = "0" * 32
    k = "01" * 24
    out = DES.feistel_function(r, k)
    assert isinstance(out, str)
    assert len(out) == 32
    assert set(out) <= {"0", "1"}


def test_end_to_end_fips_encrypt():
    data = "0123456789ABCDEF"
    key = "133457799BBCDFF1"
    _, _, Ks = DES.generate_subkeys(key)
    out_bits, _, _ = DES.des_rounds(data, Ks)
    cipher_hex = DES.binary_to_hex(out_bits)
    assert cipher_hex == "85E813540F0AB405"


def test_end_to_end_fips_decrypt():
    data = "85E813540F0AB405"
    key = "133457799BBCDFF1"
    _, _, Ks_forward = DES.generate_subkeys(key)
    Ks_reverse = Ks_forward[::-1]
    out_bits, _, _ = DES.des_rounds(data, Ks_reverse)
    plain_hex = DES.binary_to_hex(out_bits)
    assert plain_hex == "0123456789ABCDEF"


def test_roundtrip_randomized_blocks_and_keys():
    random.seed(454)
    trials = 25
    for _ in range(trials):
        data = f"{random.getrandbits(64):016X}"
        key = f"{random.getrandbits(64):016X}"
        _, _, Ks_fwd = DES.generate_subkeys(key)
        out_bits_enc, _, _ = DES.des_rounds(data, Ks_fwd)
        ct = DES.binary_to_hex(out_bits_enc)
        Ks_rev = Ks_fwd[::-1]
        out_bits_dec, _, _ = DES.des_rounds(ct, Ks_rev)
        pt = DES.binary_to_hex(out_bits_dec)
        assert pt == data


def test_roundtrip_edge_patterns():
    patterns = [
        "0000000000000000",
        "FFFFFFFFFFFFFFFF",
        "AAAAAAAAAAAAAAAA",
        "5555555555555555",
        "0123456789ABCDEF",
        "FEDCBA9876543210",
    ]
    for data in patterns:
        for key in patterns:
            _, _, Ks_fwd = DES.generate_subkeys(key)
            out_bits_enc, _, _ = DES.des_rounds(data, Ks_fwd)
            ct = DES.binary_to_hex(out_bits_enc)
            Ks_rev = Ks_fwd[::-1]
            out_bits_dec, _, _ = DES.des_rounds(ct, Ks_rev)
            pt = DES.binary_to_hex(out_bits_dec)
            assert pt == data
