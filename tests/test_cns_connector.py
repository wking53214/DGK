"""DGK's perimeter and health checks as CNS gates.

These skip where ``cns`` is not installed. CI installs the extra and sets DGK_REQUIRE_CNS=1, so there they cannot skip.
The gates are held against the real kernel: for the same request, the gate and a real
transaction agree about what happens.
"""
import math
import os

import pytest

if os.environ.get("DGK_REQUIRE_CNS") == "1":  # CI: a missing cns is a failure, not a skip
    import cns.gate as gate
else:
    gate = pytest.importorskip("cns.gate")

from dgk import Kernel  # noqa: E402
from dgk.cns_connector import (  # noqa: E402
    REQUEST_SUBJECT, TELEMETRY_SUBJECT, HealthGate, PerimeterGate, cns_chain, request_digest, telemetry_digest)
from dgk.interceptors import RuleRegistry  # noqa: E402
from dgk.taxonomy import CheckResult  # noqa: E402

OK = {"latency": 134.2, "abort_rate": 0.008, "reentry_rate": 0.04, "load_depth": 280.0, "determinism_index": 0.998}
CALLER, TOKEN = "tester", "tester-token-0123456789abcdef0123456789"
PASS, RETRY, BREACH = gate.GateOutcome.PASS, gate.GateOutcome.RETRY, gate.GateOutcome.TERMINAL_BREACH


def test_both_gates_satisfy_the_cns_protocol_at_the_alpha_end():
    for g in (PerimeterGate(), HealthGate()):
        assert isinstance(g, gate.Gate) and g.position is gate.GatePosition.ALPHA and g.name.startswith("dgk.")


def test_the_chain_holds_both_at_alpha_and_is_incomplete_by_design():
    chain = cns_chain()
    assert [g.name for g in chain.alpha] == ["dgk.perimeter", "dgk.health"] and chain.omega == ()
    assert not chain.complete() and chain.misplaced() == ()


# ------------------------------------------------------------ perimeter

def test_clean_text_passes_and_the_verdict_is_bound_to_that_text():
    result = PerimeterGate().check("hello world")
    assert result.outcome is PASS and result.binds(REQUEST_SUBJECT, request_digest("hello world"))
    assert not result.binds(REQUEST_SUBJECT, request_digest("hello there"))


@pytest.mark.parametrize("text", ["a forbidden thing", "fоrbidden", "for-bidden", "FORBIDDEN", "for​bidden"])
def test_a_forbidden_sequence_is_a_terminal_breach_however_it_is_disguised(text):
    result = PerimeterGate().check(text)
    assert result.outcome is BREACH and "perimeter_compliance_filter" in result.reason and result.bound()


def test_a_request_mapping_is_read_the_way_the_kernel_reads_it():
    chat = {"messages": [{"role": "user", "content": "something forbidden here"}]}
    assert PerimeterGate().check(chat).outcome is BREACH
    assert PerimeterGate().check({"text": "fine", "messages": [{"content": "forbidden"}]}).outcome is PASS


@pytest.mark.parametrize("bad", [None, 7, ["forbidden"], b"forbidden"])
def test_something_that_is_not_text_or_a_mapping_is_a_type_error_not_a_pass(bad):
    with pytest.raises(TypeError, match="request text or a request mapping"):
        PerimeterGate().check(bad)


def test_the_gate_uses_the_registry_it_is_given():
    class Refuse:
        name = "custom"

        def enforce(self, context):
            return CheckResult(False, "custom", "no")

    registry = RuleRegistry()
    registry.register(Refuse())
    result = PerimeterGate(registry).check("harmless")
    assert result.outcome is BREACH and result.reason == "custom: no"
    assert PerimeterGate(RuleRegistry()).check("a forbidden thing").outcome is PASS   # no rules, nothing to refuse


def test_a_rule_that_raises_is_a_breach_bound_to_the_request():
    class Explode:
        name = "explode"

        def enforce(self, context):
            raise RuntimeError("boom")

    registry = RuleRegistry()
    registry.register(Explode())
    result = PerimeterGate(registry).check("text")
    assert result.outcome is BREACH and "RuntimeError" in result.reason and result.bound()


# ------------------------------------------------------------ health

def test_healthy_telemetry_passes_bound_to_the_five_readings():
    result = HealthGate().check(OK)
    assert result.outcome is PASS and result.binds(TELEMETRY_SUBJECT, telemetry_digest(OK))


def test_extra_keys_are_allowed_and_not_part_of_what_is_bound():
    assert telemetry_digest({**OK, "note": "x"}) == telemetry_digest(OK)
    result = HealthGate().check({**OK, "note": "x"})
    assert result.outcome is PASS and result.binds(TELEMETRY_SUBJECT, telemetry_digest(OK))


@pytest.mark.parametrize("field, value, fault", [
    ("latency", 500.5, "latency_fault"), ("abort_rate", 0.26, "abort_fault"), ("reentry_rate", 2.5, "reentry_fault")])
def test_a_breached_limit_is_a_retry_naming_the_fault(field, value, fault):
    result = HealthGate().check({**OK, field: value})
    assert result.outcome is RETRY and fault in result.reason and result.bound()


def test_the_limits_are_inclusive_at_the_edge():
    assert HealthGate().check({**OK, "latency": 500.0}).outcome is PASS
    assert HealthGate().check({**OK, "latency": 500.0001}).outcome is RETRY


def test_several_faults_are_all_named():
    reason = HealthGate().check({**OK, "latency": 900, "abort_rate": 0.9}).reason
    assert "latency_fault" in reason and "abort_fault" in reason


@pytest.mark.parametrize("bad", [
    {**OK, "latency": math.nan}, {**OK, "latency": math.inf}, {**OK, "latency": -1}, {**OK, "latency": True},
    {**OK, "latency": "fast"}, {**OK, "extra": object()}])
def test_telemetry_the_kernel_would_refuse_is_a_breach_and_unbound(bad):
    result = HealthGate().check(bad)
    assert result.outcome is BREACH and not result.bound() and "nothing was judged" in result.reason


@pytest.mark.parametrize("bad", [[1, 2, 3], [("latency", 1.0)], "latency", None])
def test_telemetry_that_is_not_a_mapping_is_a_type_error_even_if_dict_could_read_it(bad):
    with pytest.raises(TypeError, match="telemetry mapping"):
        HealthGate().check(bad)


# ------------------------------------------------------------ against the real kernel

@pytest.fixture
def kernel(tmp_path):
    k = Kernel(log_path=str(tmp_path / "audit.log"))
    k.callers.register(CALLER, TOKEN, ("p",))
    yield k
    k.close()


@pytest.mark.parametrize("telemetry, text, outcome, cause", [
    (OK, "plain text", PASS, None),
    (OK, "a forbidden thing", BREACH, "PERIMETER"),
    ({**OK, "latency": 900.0}, "plain text", RETRY, "HEALTH_LIMIT"),
    ({**OK, "abort_rate": float("nan")}, "plain text", BREACH, "TELEMETRY_INVALID"),
])
def test_the_gates_and_a_real_transaction_agree_about_the_same_request(kernel, telemetry, text, outcome, cause):
    resolved = gate.resolve([PerimeterGate().check(text), HealthGate().check(telemetry)])
    done = kernel.process_transaction("p", dict(telemetry), text, CALLER, TOKEN)
    assert resolved is outcome
    assert done.get("refusal_cause") == cause
    assert (done["transaction_status"] == "COMMITTED") == (outcome is PASS)
