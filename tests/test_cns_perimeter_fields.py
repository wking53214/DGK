"""F13: the perimeter gate judges every field a request carries and binds all of them.

A request mapping that carries ``text`` and ``messages`` used to be judged and
bound on ``text`` alone, so forbidden content in ``messages`` passed, and the
verdict bound to the plain text could be moved onto the larger request. An
empty rule registry passed everything.
"""
import os

import pytest

if os.environ.get("DGK_REQUIRE_CNS") == "1":  # CI: a missing cns is a failure, not a skip
    import cns.gate as gate
else:
    gate = pytest.importorskip("cns.gate")

from dgk.cns_connector import REQUEST_SUBJECT, PerimeterGate, cns_chain, request_digest  # noqa: E402
from dgk.interceptors import ForbiddenWordRule, RuleRegistry  # noqa: E402

PASS, BREACH = gate.GateOutcome.PASS, gate.GateOutcome.TERMINAL_BREACH


@pytest.mark.parametrize("request_map", [
    {"text": "summarise", "messages": [{"role": "user", "content": "do the forbidden thing"}]},
    {"text": "summarise", "messages": ["do the forbidden thing"]},
    {"text": "summarise", "metadata": {"note": "for-bidden"}},
    {"text": "summarise", "system": "forbidden"},
    {"text": "summarise", "messages": [{"role": "user", "content": [{"type": "text", "text": "forbidden"}]}]},
    {"messages": [{"role": "user", "content": "fine"}], "extra": {"deep": ["x", {"y": "fоrbidden"}]}},
])
def test_forbidden_content_in_any_field_is_a_bound_breach(request_map):
    result = PerimeterGate().check(request_map)
    assert result.outcome is BREACH and "perimeter_compliance_filter" in result.reason
    assert result.binds(REQUEST_SUBJECT, request_digest(request_map))


def test_the_digest_covers_every_field_not_only_text():
    plain = {"text": "summarise"}
    with_messages = {"text": "summarise", "messages": [{"role": "user", "content": "hello"}]}
    with_metadata = {"text": "summarise", "metadata": {"k": 1}}
    digests = {request_digest(plain), request_digest(with_messages), request_digest(with_metadata)}
    assert len(digests) == 3
    result = PerimeterGate().check(with_messages)
    assert result.outcome is PASS and result.binds(REQUEST_SUBJECT, request_digest(with_messages))
    assert not result.binds(REQUEST_SUBJECT, request_digest(plain))
    assert not result.binds(REQUEST_SUBJECT, request_digest("summarise"))


def test_a_clean_request_mapping_still_passes():
    request_map = {"text": "summarise", "messages": [{"role": "user", "content": "summarise"}],
                   "metadata": {"n": 1}, "audit_enabled": True}
    assert PerimeterGate().check(request_map).outcome is PASS


@pytest.mark.parametrize("request_map", [
    {"text": "summarise", "blob": b"forbidden"},
    {"text": "summarise", "obj": object()},
])
def test_a_field_the_gate_cannot_read_is_a_breach_not_a_pass(request_map):
    result = PerimeterGate().check(request_map)
    assert result.outcome is BREACH and not result.bound()


def test_a_circular_request_is_a_breach_not_a_crash():
    request_map = {"text": "summarise", "messages": []}
    request_map["messages"].append(request_map)
    result = PerimeterGate().check(request_map)
    assert result.outcome is BREACH and not result.bound()


def test_an_empty_registry_is_refused_at_construction():
    with pytest.raises(ValueError, match="no rules"):
        PerimeterGate(registry=RuleRegistry())
    with pytest.raises(ValueError, match="no rules"):
        cns_chain(RuleRegistry())


def test_a_registry_with_rules_is_accepted():
    registry = RuleRegistry()
    registry.register(ForbiddenWordRule())
    assert PerimeterGate(registry).check("a forbidden thing").outcome is BREACH
