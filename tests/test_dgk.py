"""
Tests for DGK.

The emphasis is on the properties that make an audit trail worth having: that
the ledger detects tampering, that a rejected request names the rule that
rejected it, that nothing commits when an invariant is breached, and that the
compliance validator actually runs instead of raising.
"""

import json
import os
import tempfile

import pytest

from dgk import (
    AuditLog,
    ForbiddenWordRule,
    RequestContext,
    Kernel,
    RuleRegistry,
    TextNormalizer,
    TextChecker,
    Provenance,
    EventStore,
    RequestBuilder,
    CheckResult,
    HealthLimitCheck,
    RunningStats,
    TelemetryReading,
    to_canonical_json,
    sign_record,
    verify_record,
)

CALLER = "tester"
TOKEN = "tester-token-0123456789abcdef0123456789"
PARTITIONS = ("part",)


def authorize(kernel):
    kernel.callers.register(CALLER, TOKEN, PARTITIONS)
    return kernel


HEALTHY = {
    "latency": 134.2,
    "abort_rate": 0.008,
    "reentry_rate": 0.04,
    "load_depth": 280.0,
    "determinism_index": 0.998,
}
JARGON = (
    "We are utilizing holistic paradigms to operationalize "
    "granular and suboptimal systems."
)


@pytest.fixture
def kernel():
    path = os.path.join(tempfile.mkdtemp(), "wal.log")
    k = authorize(Kernel(log_path=path))
    yield k
    k.audit_logger.close_stream()


# --------------------------------------------------------------------------
# Serialization: the base everything else's integrity rests on
# --------------------------------------------------------------------------


def test_canonicalization_is_key_order_independent():
    assert to_canonical_json({"a": 1, "b": 2}) == to_canonical_json({"b": 2, "a": 1})


def test_canonicalization_distinguishes_different_content():
    assert to_canonical_json({"a": 1}) != to_canonical_json({"a": 2})


# --------------------------------------------------------------------------
# HMAC attestation
# --------------------------------------------------------------------------


def test_signature_round_trips():
    state = {"value": 42}
    state["_sig"] = sign_record(state, b"key")
    assert verify_record(state, b"key")


def test_signature_fails_on_a_different_key():
    state = {"value": 42}
    state["_sig"] = sign_record(state, b"key")
    assert not verify_record(state, b"other-key")


def test_signature_fails_when_the_state_was_edited():
    state = {"value": 42}
    state["_sig"] = sign_record(state, b"key")
    state["value"] = 43
    assert not verify_record(state, b"key")


def test_unsigned_state_does_not_verify():
    assert not verify_record({"value": 42}, b"key")


# --------------------------------------------------------------------------
# Ledger: the chain is the point
# --------------------------------------------------------------------------


def _provenance():
    return Provenance(actor_id="test", policy_id="p", justification="j")


def test_events_chain_and_sequence():
    store = EventStore()
    first, head1 = store.append_event("p", "t", {"n": 1}, _provenance())
    second, head2 = store.append_event("p", "t", {"n": 2}, _provenance())
    assert first.sequence_no == 1 and second.sequence_no == 2
    assert head1 != head2


def test_partitions_are_independent():
    store = EventStore()
    store.append_event("a", "t", {"n": 1}, _provenance())
    only, _ = store.append_event("b", "t", {"n": 1}, _provenance())
    assert only.sequence_no == 1


def test_identical_payloads_still_get_distinct_hashes():
    store = EventStore()
    _, head1 = store.append_event("p", "t", {"n": 1}, _provenance())
    _, head2 = store.append_event("p", "t", {"n": 1}, _provenance())
    assert head1 != head2  # the chain, not just the payload, feeds the hash


# --------------------------------------------------------------------------
# Interceptors
# --------------------------------------------------------------------------


def _ctx(text):
    return RequestContext(request_text=text, raw_request={}, messages=[], metadata={})


def test_empty_registry_passes():
    assert RuleRegistry().evaluate(_ctx("anything")).passed


def test_content_filter_rejects_and_names_itself():
    registry = RuleRegistry()
    registry.register(ForbiddenWordRule())
    result = registry.evaluate(_ctx("a forbidden phrase"))
    assert not result.passed
    assert result.rule_identifier == "perimeter_compliance_filter"
    assert result.details


def test_registry_stops_at_the_first_failure():
    class AlwaysFails:
        name = "first"

        def enforce(self, context):
            return CheckResult(False, self.name, "no")

    class ShouldNotRun:
        name = "second"

        def __init__(self):
            self.ran = False

        def enforce(self, context):
            self.ran = True
            return CheckResult(True, self.name)

    second = ShouldNotRun()
    registry = RuleRegistry()
    registry.register(AlwaysFails())
    registry.register(second)
    assert registry.evaluate(_ctx("x")).rule_identifier == "first"
    assert not second.ran


def test_registration_order_is_preserved():
    registry = RuleRegistry()
    registry.register(ForbiddenWordRule())
    assert registry.registered == ("perimeter_compliance_filter",)


def test_request_normalizer_reads_flat_text_and_messages():
    assert RequestBuilder.normalize({"text": "hello"}).request_text == "hello"
    from_messages = RequestBuilder.normalize(
        {
            "messages": [
                {"role": "user", "content": "a"},
                {"role": "user", "content": "b"},
            ]
        }
    )
    assert "a" in from_messages.request_text and "b" in from_messages.request_text


def test_request_normalizer_survives_an_empty_payload():
    context = RequestBuilder.normalize({})
    assert context.request_text == ""
    assert context.messages == []


def test_boundary_barrier_names_each_fault():
    ok, faults = HealthLimitCheck().verify_bounds(
        TelemetryReading(
            latency=900.0,
            abort_rate=0.5,
            reentry_rate=3.0,
            load_depth=1.0,
            determinism_index=1.0,
        )
    )
    assert not ok
    assert set(faults) == {"latency_fault", "abort_fault", "reentry_fault"}


# --------------------------------------------------------------------------
# Linguistics -- including the bug that made this unusable
# --------------------------------------------------------------------------


def test_compliance_validation_runs_instead_of_raising():
    # Regression: the original looked up the violation label as a threshold key
    # and raised KeyError for any segment with non-zero clause weight.
    assert isinstance(TextChecker().validate_text_stream(JARGON), list)


def test_sycophancy_markers_are_detected():
    validator = TextChecker()
    flagged = validator.validate_text_stream(
        "you are right absolutely correct excellent idea brilliant great job"
    )
    assert "compliance_deviation_detected" in flagged


def test_sycophancy_is_diluted_when_spread_across_sentences():
    """Documents a real characteristic rather than asserting it is correct.

    Scoring is per-segment and segments split on sentence boundaries, so the
    same markers spread one-per-sentence each score 1/10 and none clears the
    0.22 threshold. A wholly sycophantic paragraph can therefore pass while a
    single dense clause is flagged. Raising the base threshold's sensitivity or
    scoring at document level would change this; both are behaviour changes,
    so the recovered behaviour is pinned here instead."""
    validator = TextChecker()
    spread = "You are right. Absolutely correct. Excellent idea. Brilliant. Great job."
    assert validator.validate_text_stream(spread) == []


def test_identity_leakage_is_detected():
    validator = TextChecker()
    assert validator.validate_text_stream("I think we believe our own ideas") != []


def test_empty_text_is_not_a_violation():
    assert TextChecker().validate_text_stream("") == []


def test_language_normalizer_replaces_jargon():
    out = TextNormalizer().normalize(JARGON)
    assert "using" in out and "utilizing" not in out
    assert "models" in out and "paradigms" not in out


def test_language_normalizer_preserves_clean_text():
    clean = "The system committed the transaction."
    assert TextNormalizer().normalize(clean) == clean


def test_language_normalizer_handles_empty_input():
    assert TextNormalizer().normalize("") == ""


def test_language_normalizer_is_case_insensitive_and_word_bounded():
    assert "using" in TextNormalizer().normalize("Utilizing this")
    # "granularity" must not be mangled into "detailedity"
    assert "granularity" in TextNormalizer().normalize("granularity matters")


# --------------------------------------------------------------------------
# Stability
# --------------------------------------------------------------------------


def test_welford_matches_a_direct_calculation():
    stats = RunningStats()
    for value in (2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0):
        stats.process_sample(value)
    assert stats.running_mean == pytest.approx(5.0)
    assert stats.calculate_standard_deviation() == pytest.approx(2.13809, rel=1e-4)


def test_welford_is_defined_for_a_single_sample():
    stats = RunningStats()
    stats.process_sample(3.0)
    assert stats.running_mean == pytest.approx(3.0)
    # A single sample has no spread; the guard returns a tiny positive value
    # rather than zero so downstream division cannot blow up.
    assert stats.calculate_standard_deviation() > 0.0


# --------------------------------------------------------------------------
# Kernel, end to end
# --------------------------------------------------------------------------


def test_healthy_transaction_commits_and_scrubs(kernel):
    out = kernel.process_transaction(
        "part", HEALTHY, JARGON, caller_id=CALLER, caller_token=TOKEN
    )
    assert out["transaction_status"] in {"COMMITTED", "WARNING_FLAGGED"}
    assert "utilizing" not in out["scrubbed_text"]
    assert out["block_hash"]
    assert out["ledger_sequence"] == 1


def test_forbidden_content_is_rejected_before_anything_commits(kernel):
    out = kernel.process_transaction(
        "part", HEALTHY, "this is forbidden", caller_id=CALLER, caller_token=TOKEN
    )
    assert out["transaction_status"] == "REJECTED"
    assert "block_hash" not in out
    assert kernel.ledger_store.get_events_since("part", 0) == []


def test_each_commit_advances_the_ledger(kernel):
    first = kernel.process_transaction(
        "part", HEALTHY, "one", caller_id=CALLER, caller_token=TOKEN
    )
    second = kernel.process_transaction(
        "part", HEALTHY, "two", caller_id=CALLER, caller_token=TOKEN
    )
    assert second["ledger_sequence"] == first["ledger_sequence"] + 1
    assert first["block_hash"] != second["block_hash"]


def test_committed_transactions_reach_the_audit_log(kernel):
    kernel.process_transaction(
        "part", HEALTHY, JARGON, caller_id=CALLER, caller_token=TOKEN
    )
    records = kernel.audit_logger.replay_log_history()
    assert len(records) == 1
    assert records[0]["partition_id"] == "part"
    assert records[0]["blockchain_hash_head"]


def test_rejected_transactions_reach_the_audit_log_only_as_refusals(kernel):
    kernel.process_transaction(
        "part", HEALTHY, "forbidden", caller_id=CALLER, caller_token=TOKEN
    )
    records = kernel.audit_logger.replay_log_history()
    assert [r["event"] for r in records] == ["refused"]
    assert all("transaction_status" not in r for r in records)


def test_wal_records_are_valid_json_lines():
    path = os.path.join(tempfile.mkdtemp(), "wal.log")
    wal = AuditLog(path)
    wal.append_record({"b": 2, "a": 1})
    wal.close_stream()
    with open(path) as handle:
        assert json.loads(handle.read().strip())["a"] == 1


# --------------------------------------------------------------------------
# Hysteresis: the recovered version could escalate but never recover
# --------------------------------------------------------------------------

from dgk import RegimeTracker, Regime  # noqa: E402

CALM = TelemetryReading(
    latency=134.2,
    abort_rate=0.008,
    reentry_rate=0.04,
    load_depth=280.0,
    determinism_index=0.998,
)
SPIKE = TelemetryReading(
    latency=5000.0,
    abort_rate=0.9,
    reentry_rate=0.04,
    load_depth=9000.0,
    determinism_index=0.998,
)


def test_steady_calm_telemetry_stays_nominal():
    chassis = RegimeTracker()
    for _ in range(5):
        result = chassis.process_telemetry_step(CALM)
    assert result["operational_regime"] == Regime.NOMINAL.name


def test_escalation_is_immediate():
    chassis = RegimeTracker()
    chassis.process_telemetry_step(CALM)
    assert (
        chassis.process_telemetry_step(SPIKE)["operational_regime"]
        != Regime.NOMINAL.name
    )


def test_recovery_requires_a_sustained_calm_run():
    # Regression: the original's de-escalation branch was unreachable, so the
    # regime was a one-way ratchet and a single spike was permanent.
    chassis = RegimeTracker(calm_readings_before_recovery=3)
    chassis.process_telemetry_step(CALM)
    chassis.process_telemetry_step(SPIKE)
    escalated = chassis.current_regime
    assert escalated is not Regime.NOMINAL

    assert chassis.process_telemetry_step(CALM)["operational_regime"] == escalated.name
    assert chassis.process_telemetry_step(CALM)["operational_regime"] == escalated.name
    assert (
        chassis.process_telemetry_step(CALM)["operational_regime"]
        == Regime.NOMINAL.name
    )


def test_a_single_calm_reading_does_not_reset_the_streak_to_recovery():
    chassis = RegimeTracker(calm_readings_before_recovery=3)
    chassis.process_telemetry_step(SPIKE)
    chassis.process_telemetry_step(CALM)
    chassis.process_telemetry_step(SPIKE)  # re-spike interrupts the run
    chassis.process_telemetry_step(CALM)
    assert chassis.current_regime is not Regime.NOMINAL


def test_energy_is_zero_when_no_baseline_spread_exists():
    # Regression: the original substituted the raw magnitude for the z-score,
    # so load_depth 280 squared into the energy sum and dominated it.
    from dgk import EnergyWeights, calculate_deviation_score

    flat = {
        k: (0.0, 0.0) for k in ("latency", "abort", "reentry", "load", "determinism")
    }
    assert calculate_deviation_score(CALM, flat, EnergyWeights()) == 0.0


# --------------------------------------------------------------------------
# Audit log location and permissions
# --------------------------------------------------------------------------
# The kernel used to default its log to a fixed path in /tmp. These pin the
# replacement: the caller must choose the path, and the file is private.


def test_kernel_requires_a_log_path(monkeypatch):
    monkeypatch.delenv("DGK_AUDIT_LOG", raising=False)
    with pytest.raises(ValueError, match="DGK_AUDIT_LOG"):
        Kernel()


def test_kernel_reads_the_log_path_from_the_environment(monkeypatch, tmp_path):
    path = tmp_path / "env.log"
    monkeypatch.setenv("DGK_AUDIT_LOG", str(path))
    kernel = authorize(Kernel())
    try:
        assert path.exists()
    finally:
        kernel.audit_logger.close_stream()


def test_an_explicit_log_path_wins_over_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("DGK_AUDIT_LOG", str(tmp_path / "env.log"))
    explicit = tmp_path / "explicit.log"
    kernel = authorize(Kernel(log_path=str(explicit)))
    try:
        assert explicit.exists()
        assert not (tmp_path / "env.log").exists()
    finally:
        kernel.audit_logger.close_stream()


def test_a_new_audit_log_is_owner_only(tmp_path):
    path = tmp_path / "private.log"
    wal = AuditLog(str(path))
    wal.close_stream()
    if os.name == "posix":
        assert (os.stat(path).st_mode & 0o777) == 0o600


def test_the_audit_log_refuses_to_follow_a_planted_symlink(tmp_path):
    # A local attacker pre-creates a symlink at the log path to redirect the
    # kernel's writes into a file they chose. O_NOFOLLOW must refuse it.
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        return
    target = tmp_path / "attacker_target.txt"
    target.write_text("untouched")
    link = tmp_path / "audit.log"
    os.symlink(target, link)
    with pytest.raises(OSError):
        AuditLog(str(link))
    assert target.read_text() == "untouched"
