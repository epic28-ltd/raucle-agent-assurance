# SPDX-License-Identifier: Apache-2.0
"""W3C Trace Context parsing and formatting (issue 111, category 1/2 tests).

The parser is the untrusted-input boundary for externally supplied trace
headers: every malformed input must be dropped (None), never raise, and never
grow unbounded. Format helpers are for values this code base produces itself
and fail loudly on invalid input.
"""

from __future__ import annotations

import pytest
from oaa_instrumentation.w3c_tracecontext import (
    TRACEPARENT_MAX_LENGTH,
    TRACESTATE_MAX_KEY_LENGTH,
    TRACESTATE_MAX_LENGTH,
    TRACESTATE_MAX_MEMBERS,
    TRACESTATE_MAX_VALUE_LENGTH,
    format_traceparent,
    format_tracestate,
    parse_context,
    parse_traceparent,
    parse_tracestate,
)

VALID_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
VALID_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
VALID_PARENT_ID = "00f067aa0ba902b7"
VALID_TRACESTATE = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"


# -- traceparent: valid ------------------------------------------------------


def test_parse_valid_traceparent() -> None:
    ctx = parse_traceparent(VALID_TRACEPARENT)
    assert ctx is not None
    assert ctx.version == "00"
    assert ctx.trace_id == VALID_TRACE_ID
    assert ctx.parent_span_id == VALID_PARENT_ID
    assert ctx.trace_flags == "01"
    assert ctx.tracestate == ()


def test_parse_traceparent_surrounding_whitespace_stripped() -> None:
    assert parse_traceparent(f"  {VALID_TRACEPARENT}\t") is not None


@pytest.mark.parametrize("flags", ["00", "01", "03", "ff"])
def test_parse_traceparent_any_two_hex_flags(flags: str) -> None:
    header = f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-{flags}"
    assert parse_traceparent(header) is not None


def test_parse_traceparent_future_version_with_extra_fields() -> None:
    header = f"42-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01-anything-else"
    ctx = parse_traceparent(header)
    assert ctx is not None
    assert ctx.version == "42"


# -- traceparent: malformed (category 2: drop, never crash) -------------------


@pytest.mark.parametrize(
    "header",
    [
        "",
        "   ",
        "00",
        "00-",
        f"{VALID_TRACE_ID}-{VALID_PARENT_ID}-01",  # missing version
        f"00--{VALID_PARENT_ID}-01",  # empty trace id
        f"00-{VALID_TRACE_ID}--01",  # empty parent id
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}",  # missing flags
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01-02",  # 5 fields on version 00
        f"ff-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01",  # version ff is reserved
        f"0g-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01",  # non-hex version
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",  # 31-char trace id
        f"00-4bf92f3577b34da6a3ce929d0e0e47366-{VALID_PARENT_ID}-01",  # 33-char trace id
        f"00-{VALID_TRACE_ID}-00f067aa0ba902b-01",  # 15-char parent id
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-0",  # 1-char flags
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-011",  # 3-char flags
        f"00-{VALID_TRACE_ID.upper()}-{VALID_PARENT_ID}-01",  # uppercase hex
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID.upper()}-01",  # uppercase parent
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-0G",  # non-hex flags
        f"00-00000000000000000000000000000000-{VALID_PARENT_ID}-01",  # zero trace id
        f"00-{VALID_TRACE_ID}-0000000000000000-01",  # zero parent id
        f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01 {VALID_TRACE_ID}",  # trailing junk
        "00,4bf92f3577b34da6a3ce929d0e0e4736,00f067aa0ba902b7,01",  # wrong separator
        "garbage header value",
        "-" * 55,
        "00-" + "-" * 50,
        "a" * TRACEPARENT_MAX_LENGTH,  # at the length cap, still malformed hex
        "x" * (TRACEPARENT_MAX_LENGTH + 1),  # over the length cap
        None,
        123,
        4.5,
        b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        ["00", VALID_TRACE_ID, VALID_PARENT_ID, "01"],
        {"traceparent": VALID_TRACEPARENT},
        object(),
    ],
)
def test_parse_traceparent_malformed_is_dropped(header: object) -> None:
    assert parse_traceparent(header) is None


def test_parse_traceparent_rejects_internal_whitespace() -> None:
    assert parse_traceparent(f"00-{VALID_TRACE_ID} -{VALID_PARENT_ID}-01") is None


# -- tracestate --------------------------------------------------------------


def test_parse_tracestate_two_members() -> None:
    members = parse_tracestate(VALID_TRACESTATE)
    assert members == [("congo", "t61rcWkgMzE"), ("rojo", "00f067aa0ba902b7")]


def test_parse_tracestate_ows_around_members() -> None:
    assert parse_tracestate("  congo=t61rcWkgMzE ,\trojo=00f067aa0ba902b7  ") == [
        ("congo", "t61rcWkgMzE"),
        ("rojo", "00f067aa0ba902b7"),
    ]


def test_parse_tracestate_empty_is_empty_list() -> None:
    assert parse_tracestate("") == []
    assert parse_tracestate("   ") == []


def test_parse_tracestate_multi_tenant_key() -> None:
    assert parse_tracestate("tenant-id@system-id=v") == [("tenant-id@system-id", "v")]


def test_parse_tracestate_duplicate_keys_keep_first() -> None:
    assert parse_tracestate("a=1,b=2,a=3") == [("a", "1"), ("b", "2")]


def test_parse_tracestate_member_cap_is_32() -> None:
    ok = ",".join(f"k{i}=v{i}" for i in range(TRACESTATE_MAX_MEMBERS))
    assert len(parse_tracestate(ok) or []) == TRACESTATE_MAX_MEMBERS
    over = ",".join(f"k{i}=v{i}" for i in range(TRACESTATE_MAX_MEMBERS + 1))
    assert parse_tracestate(over) is None


def test_parse_tracestate_length_bound() -> None:
    assert parse_tracestate("x" * (TRACESTATE_MAX_LENGTH + 1)) is None


@pytest.mark.parametrize(
    "header",
    [
        "a=",  # empty value
        "=b",  # empty key
        "abc",  # no equals
        "a=b=c",  # equals inside value
        "A=b",  # uppercase key
        "1a=b",  # digit-first key
        "a@b@=v",  # malformed multi-tenant key
        "a b=v",  # space inside key
        "a=,b=2",  # empty value mid-list (spec: value requires one char)
        "a=b,c",  # second member malformed
        None,
        123,
        ["a=1"],
        object(),
    ],
)
def test_parse_tracestate_invalid_member_drops_whole_header(header: object) -> None:
    assert parse_tracestate(header) is None


def test_parse_tracestate_skips_empty_list_members() -> None:
    # W3C list grammar (list-member = (key "=" value) / OWS): empty and
    # whitespace-only list members are allowed because some vendors inject
    # whitespace after commas; they are skipped, not fatal.
    assert parse_tracestate("a=1,,b=2") == [("a", "1"), ("b", "2")]
    assert parse_tracestate("a=1, ,b=2") == [("a", "1"), ("b", "2")]
    assert parse_tracestate(",a=1") == [("a", "1")]
    assert parse_tracestate("a=1,") == [("a", "1")]
    assert parse_tracestate(",,") == []


def test_parse_tracestate_value_grammar_is_w3c_exact() -> None:
    # value = 0*255(chr) nblk-chr: an interior space is a value character
    # and survives parsing; whitespace around a member or the header is
    # OWS and is ignored. A tab is neither: not a value character.
    assert parse_tracestate("k=a b") == [("k", "a b")]
    assert parse_tracestate("k=a b , j=c") == [("k", "a b"), ("j", "c")]
    assert parse_tracestate("k=a\tb") is None


def test_parse_tracestate_multi_tenant_sublengths() -> None:
    # tenant-id 1 + 0*240; system-id 1 + 0*13 (256 total key cap unchanged).
    assert parse_tracestate(f"{'k' * 241}@sys=v") is not None
    assert parse_tracestate(f"{'k' * 242}@sys=v") is None
    assert parse_tracestate(f"t@{'s' * 14}=v") is not None
    assert parse_tracestate(f"t@{'s' * 15}=v") is None


def test_parse_tracestate_digit_initial_tenant_id() -> None:
    # tenant-id = ( lcalpha / DIGIT ) ...: digit-initial tenant ids are
    # valid; simple keys still require a lowercase-letter initial.
    assert parse_tracestate("0tenant@sys=v") == [("0tenant@sys", "v")]
    assert parse_tracestate("12@sys=v") == [("12@sys", "v")]


def test_parse_tracestate_value_bound() -> None:
    assert parse_tracestate(f"k={'v' * TRACESTATE_MAX_VALUE_LENGTH}") is not None
    assert parse_tracestate(f"k={'v' * (TRACESTATE_MAX_VALUE_LENGTH + 1)}") is None


def test_parse_tracestate_key_bound() -> None:
    assert parse_tracestate(f"{'k' * TRACESTATE_MAX_KEY_LENGTH}=v") is not None
    assert parse_tracestate(f"{'k' * (TRACESTATE_MAX_KEY_LENGTH + 1)}=v") is None


# -- parse_context: traceparent is independent of tracestate ------------------


def test_parse_context_valid_pair() -> None:
    ctx = parse_context(VALID_TRACEPARENT, VALID_TRACESTATE)
    assert ctx is not None
    assert ctx.trace_id == VALID_TRACE_ID
    assert ctx.tracestate == (("congo", "t61rcWkgMzE"), ("rojo", "00f067aa0ba902b7"))


def test_parse_context_invalid_tracestate_keeps_traceparent() -> None:
    ctx = parse_context(VALID_TRACEPARENT, "a=b=c")
    assert ctx is not None
    assert ctx.tracestate == ()


def test_parse_context_invalid_traceparent_drops_everything() -> None:
    assert parse_context("not-a-traceparent", VALID_TRACESTATE) is None
    assert parse_context(None, VALID_TRACESTATE) is None


def test_parse_context_tracestate_optional() -> None:
    ctx = parse_context(VALID_TRACEPARENT)
    assert ctx is not None
    assert ctx.tracestate == ()


# -- formatting (values this code base produces) ------------------------------


def test_format_traceparent_round_trip() -> None:
    parsed = parse_traceparent(VALID_TRACEPARENT)
    assert parsed is not None
    assert (
        format_traceparent(
            parsed.trace_id, parsed.parent_span_id, version=parsed.version, trace_flags="01"
        )
        == VALID_TRACEPARENT
    )


def test_format_traceparent_defaults() -> None:
    header = format_traceparent(VALID_TRACE_ID, VALID_PARENT_ID)
    assert header == f"00-{VALID_TRACE_ID}-{VALID_PARENT_ID}-01"
    assert parse_traceparent(header) is not None


@pytest.mark.parametrize(
    ("trace_id", "parent_id", "kwargs"),
    [
        ("0" * 32, VALID_PARENT_ID, {}),  # zero trace id
        (VALID_TRACE_ID, "0" * 16, {}),  # zero parent id
        ("short", VALID_PARENT_ID, {}),  # wrong length
        (VALID_TRACE_ID.upper(), VALID_PARENT_ID, {}),  # uppercase
        (VALID_TRACE_ID, VALID_PARENT_ID, {"version": "ff"}),  # reserved version
        (VALID_TRACE_ID, VALID_PARENT_ID, {"version": "xyz"}),  # non-hex version
        (VALID_TRACE_ID, VALID_PARENT_ID, {"trace_flags": "0G"}),
    ],
)
def test_format_traceparent_rejects_invalid_input(
    trace_id: str, parent_id: str, kwargs: dict
) -> None:
    with pytest.raises(ValueError, match="traceparent"):
        format_traceparent(trace_id, parent_id, **kwargs)


def test_format_tracestate_round_trip() -> None:
    members = parse_tracestate(VALID_TRACESTATE)
    assert members is not None
    assert format_tracestate(members) == VALID_TRACESTATE


def test_format_tracestate_empty() -> None:
    assert format_tracestate([]) == ""


@pytest.mark.parametrize(
    "members",
    [
        [("", "v")],
        [("k", "")],
        [("a", "b=c")],
        [("A", "v")],
        [("a", "b,c")],  # comma would split the member on the wire
        [("a", "b ")],  # trailing space: final value char must be non-blank
    ],
)
def test_format_tracestate_rejects_invalid_members(members: list) -> None:
    with pytest.raises(ValueError, match="tracestate"):
        format_tracestate(members)
