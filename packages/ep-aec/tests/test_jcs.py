# SPDX-License-Identifier: Apache-2.0
"""JCS (RFC 8785) tests: key ordering by UTF-16 code units, ES6 number
formatting, string escaping — against the draft's known tricky cases."""

from __future__ import annotations

import pytest

from oaa_epaec.objects import jcs, jcs_digest


class TestKeyOrdering:
    def test_simple_order(self):
        assert jcs({"b": 1, "a": 2}) == '{"a":2,"b":1}'
        assert jcs({"b": 2, "a": 1, "c": 3}) == '{"a":1,"b":2,"c":3}'

    def test_utf16_code_unit_order(self):
        # RFC 8785: sort by UTF-16 code units. "A" (U+0041) sorts before a
        # lone high surrogate (U+D800) — code-unit order, not code-point.
        assert jcs({"A": 1}) == '{"A":1}'
        out = jcs({"\ud800": 1, "A": 2})
        assert out == '{"A":2,"\\ud800":1}'

    def test_basic_multilingual_vs_astral(self):
        # Discriminating case: U+E000 (one 16-bit unit) vs U+10000 (units
        # D800 DC00). Code-point order says E000 first; UTF-16 code-unit
        # order says the astral lead unit D800 sorts first.
        out = jcs({chr(0x10000): 1, chr(0xE000): 2})
        # UTF-16 code units: 0xD800 (astral lead) < 0xE000 → astral sorts FIRST
        assert out == '{"' + chr(0x10000) + '":1,"' + chr(0xE000) + '":2}'
        # Python's code-point sort disagrees, pinning the RFC's UTF-16 rule:
        assert sorted([chr(0xE000), chr(0x10000)]) == [chr(0xE000), chr(0x10000)]
        assert sorted([chr(0xE000), chr(0x10000)], key=lambda s: s.encode("utf-16-be")) == [
            chr(0x10000),
            chr(0xE000),
        ]

    def test_long_vs_prefixed(self):
        # Shorter key that is a prefix sorts before the longer one.
        assert jcs({"ab": 1, "a": 2}) == '{"a":2,"ab":1}'

    def test_nested_objects_sorted_at_every_level(self):
        out = jcs({"z": {"d": 1, "a": 2}, "a": 3})
        assert out == '{"a":3,"z":{"a":2,"d":1}}'


class TestNumberFormatting:
    @pytest.mark.parametrize(
        ("value", "want"),
        [
            (1, "1"),
            (1.0, "1"),
            (-1, "-1"),
            (0, "0"),
            (-0.0, "0"),  # RFC 8785 sample: -0 collapses to "0"
            (0.1, "0.1"),
            (0.5, "0.5"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),  # ES6 exponent threshold at n = -6
            (1e21, "1e+21"),  # ES6 switches to exponential at n > 21
            (1e30, "1e+30"),
            (1.5e21, "1.5e+21"),
            (1e20, "100000000000000000000"),  # integer-valued, <=21 digits
            (333333333.33, "333333333.33"),
            (0.30000000000000004, "0.30000000000000004"),
            (5e-324, "5e-324"),  # subnormal minimum
            (9007199254740992, "9007199254740992"),
            (2.5, "2.5"),
        ],
    )
    def test_es6_format(self, value, want):
        assert jcs(value) == want
        if not isinstance(value, int) or abs(value) <= 2**53:
            assert float(jcs(float(value))) == float(want) or jcs(value) == want

    def test_large_integer_rejected(self):
        # I-JSON: integers must survive an IEEE-754 double round-trip.
        with pytest.raises(ValueError, match="not exactly representable"):
            jcs(2**53 + 1)

    def test_nonfinite_rejected(self):
        for bad in (float("inf"), float("-inf")):
            with pytest.raises(ValueError, match="finite"):
                jcs(bad)
        with pytest.raises(ValueError, match="finite"):
            jcs([float("nan")])


class TestStringsAndLiterals:
    def test_escapes(self):
        assert jcs('he"llo\\x') == '"he\\"llo\\\\x"'
        assert jcs("a\nb\tc") == '"a\\nb\\tc"'
        assert jcs("\x01") == '"\\u0001"'
        assert jcs("café ☃") == '"café ☃"'  # non-ASCII stays literal

    def test_literals(self):
        for value, want in ((None, "null"), (True, "true"), (False, "false")):
            assert jcs(value) == want

    def test_arrays_and_roundtrip(self):
        assert jcs([1, "two", None, True, [2, {"x": 1}]]) == '[1,"two",null,true,[2,{"x":1}]]'

    def test_rejected_types(self):
        with pytest.raises(TypeError):
            jcs({1: "x"})
        with pytest.raises(TypeError):
            jcs(object())

    def test_digest_stability(self):
        assert jcs_digest({"a": 1}) == jcs_digest({"a": 1.0})
        assert jcs_digest({"a": 1, "b": 2}) == jcs_digest({"b": 2, "a": 1})
        assert jcs_digest({"a": 1}).startswith("sha256:")
