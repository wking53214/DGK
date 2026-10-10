"""What a restart, a crash, or someone with write access can and cannot do."""

import json
import os

import pytest

from dgk import (
    AnchorMismatch,
    AuditLog,
    EventStore,
    FileHeadAnchor,
    Kernel,
    LedgerAuditMismatch,
    Provenance,
    RefusalBudget,
)

CALLER = "ops"
TOKEN = "ops-token-" + "z" * 40
OK = {
    "latency": 100.0,
    "abort_rate": 0.01,
    "reentry_rate": 0.1,
    "load_depth": 10.0,
    "determinism_index": 0.99,
}
STRESS = {
    "latency": 480.0,
    "abort_rate": 0.24,
    "reentry_rate": 1.9,
    "load_depth": 5000.0,
    "determinism_index": 0.99,
}
PROV = Provenance(actor_id="t", policy_id="p", justification="j")


def make(path, **kwargs):
    kernel = Kernel(log_path=str(path), **kwargs)
    kernel.callers.register(CALLER, TOKEN, ["p", "q"])
    return kernel


def run(kernel, telemetry=OK, text="fine", partition="p"):
    return kernel.process_transaction(partition, telemetry, text, CALLER, TOKEN)


def regime(kernel):
    return kernel.hysteresis_chassis.current_regime


# ---- The regime survives a restart ------------------------------------------


def test_regime_is_rebuilt_from_the_trail_after_a_restart(tmp_path):
    path = tmp_path / "a.log"
    first = make(path)
    for _ in range(4):
        run(first, STRESS)
    stressed = regime(first)
    streak = first.hysteresis_chassis._calm_streak
    first.close()
    assert stressed.name != "NOMINAL"

    second = make(path)
    assert regime(second) == stressed
    assert second.hysteresis_chassis._calm_streak == streak
    second.close()


def test_refused_readings_count_toward_the_rebuilt_regime(tmp_path):
    """A health breach is refused, never committed, and still moved the live
    classifier. The restart has to count it or it forgets the worst readings."""
    path = tmp_path / "a.log"
    first = make(path)
    run(first)
    for _ in range(4):
        result = run(first, dict(STRESS, latency=900.0))
        assert result["refusal_cause"] == "HEALTH_LIMIT"
    live = (regime(first), first.hysteresis_chassis.classifier_engine
            .analytics_orchestrator.generate_snapshot())
    first.close()
    second = make(path)
    rebuilt = (regime(second), second.hysteresis_chassis.classifier_engine
               .analytics_orchestrator.generate_snapshot())
    assert rebuilt == live
    second.close()


def test_rebuilt_state_gives_the_same_next_answer_as_the_live_one(tmp_path):
    path = tmp_path / "a.log"
    live = make(path)
    for t in (OK, STRESS, OK, STRESS):
        run(live, t)
    expected = run(live, OK)["stability_profile"]
    live.close()

    replay_path = tmp_path / "b.log"
    again = make(replay_path)
    for t in (OK, STRESS, OK, STRESS):
        run(again, t)
    again.close()
    restarted = make(replay_path)
    assert run(restarted, OK)["stability_profile"] == expected
    restarted.close()


def test_identity_and_invalid_readings_never_reach_the_classifier_or_the_replay(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    k.process_transaction("p", OK, "x", CALLER, "wrong")
    run(k, dict(OK, latency=float("nan")))
    records = k.audit_logger.replay_log_history()
    assert all("telemetry_reading" not in r for r in records)
    k.close()


# ---- A crash can leave half a line ------------------------------------------


def test_a_torn_last_audit_line_is_cut_and_recorded(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    run(k)
    k.close()
    with open(path, "a") as f:
        f.write('{"event": "refus')
    restarted = make(path)
    records = restarted.audit_logger.replay_log_history()
    assert records[-1]["event"] == "recovered_torn_tail"
    assert records[-1]["dropped_bytes"] == len('{"event": "refus')
    restarted.close()


def test_a_whole_record_missing_only_its_newline_is_kept(tmp_path):
    path = tmp_path / "a.log"
    log = AuditLog(str(path))
    log.append_record({"n": 1})
    log.append_record({"n": 2})
    log.close_stream()
    data = open(path, "rb").read()
    open(path, "wb").write(data.rstrip(b"\n"))
    reopened = AuditLog(str(path))
    assert [r["n"] for r in reopened.replay_log_history()] == [1, 2]
    assert reopened.recovered_bytes == 0
    reopened.close_stream()


def test_damage_before_the_last_line_still_fails_closed(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    run(k)
    run(k)
    k.close()
    lines = open(path).read().splitlines()
    lines[0] = lines[0][:-5]
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="audit record 1 is not valid JSON"):
        make(path)


def test_a_tampered_last_audit_line_is_not_mistaken_for_a_torn_one(tmp_path):
    path = tmp_path / "a.log"
    log = AuditLog(str(path))
    log.append_record({"n": 1})
    log.append_record({"n": 2})
    log.close_stream()
    lines = open(path).read().splitlines()
    forged = json.loads(lines[1])
    forged["n"] = 99
    open(path, "w").write(lines[0] + "\n" + json.dumps(forged))
    reopened = AuditLog(str(path))
    assert [r["n"] for r in reopened.replay_log_history()[:1]] == [1]
    assert reopened.recovered_bytes > 0
    assert all(r.get("n") != 99 for r in reopened.replay_log_history())
    reopened.close_stream()


def test_a_torn_last_ledger_line_is_dropped(tmp_path):
    path = str(tmp_path / "l.log")
    store = EventStore(path=path)
    store.append_event("p", "telemetry_update", {"a": 1}, PROV)
    store.close()
    with open(path, "a") as f:
        f.write('{"event_id": "x", "entity')
    reopened = EventStore(path=path)
    assert reopened.event_count("p") == 1
    assert reopened.recovered_bytes > 0
    assert reopened.verify_chain("p")
    reopened.close()


# ---- Ledger against trail ----------------------------------------------------


def test_cutting_back_the_ledger_alone_is_detected(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    for _ in range(3):
        run(k)
    k.close()
    ledger = str(path) + ".ledger"
    lines = open(ledger).read().splitlines()
    open(ledger, "w").write("\n".join(lines[:-1]) + "\n")
    with pytest.raises(LedgerAuditMismatch):
        make(path)


def test_rewriting_a_ledger_event_with_a_recomputed_chain_is_detected(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    for _ in range(2):
        run(k)
    k.close()
    ledger = str(path) + ".ledger"
    rewritten = EventStore()
    rows = [json.loads(l) for l in open(ledger).read().splitlines()]
    for row in rows:
        rewritten.append_event(
            row["entity_id"], row["event_type"],
            dict(row["delta"], latency=1.0),
            Provenance(row["actor_id"], row["policy_id"], row["justification"]),
        )
    forged = []
    for row, event in zip(rows, rewritten.get_events_since("p", 0)):
        row = dict(row, delta=event.delta, event_id=event.event_id,
                   hash=rewritten.hash_at("p", event.sequence_no))
        forged.append(json.dumps(row, sort_keys=True))
    open(ledger, "w").write("\n".join(forged) + "\n")
    assert EventStore(path=ledger).verify_chain("p")  # the unkeyed chain accepts it
    with pytest.raises(LedgerAuditMismatch):
        make(path)


def test_a_commit_lost_between_ledger_and_audit_is_reconciled(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    run(k)
    k.ledger_store.append_event("p", "telemetry_update", OK, PROV)  # crash before audit
    k.close()
    restarted = make(path)
    last = restarted.audit_logger.replay_log_history()[-1]
    assert last["event"] == "reconciled_ledger_commit"
    assert last["stream_sequence_index"] == 2
    restarted.close()
    again = make(path)  # and the next start is clean
    assert again.audit_logger.replay_log_history()[-1]["event"] == "reconciled_ledger_commit"
    again.close()


def test_two_unaudited_ledger_events_are_not_a_crash(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    run(k)
    for _ in range(2):
        k.ledger_store.append_event("p", "telemetry_update", OK, PROV)
    k.close()
    with pytest.raises(LedgerAuditMismatch, match="at most one"):
        make(path)


# ---- Anchor ------------------------------------------------------------------


def test_cutting_back_ledger_and_trail_together_is_caught_by_the_anchor(tmp_path):
    anchor_path = tmp_path / "anchor.log"
    path = tmp_path / "a.log"
    k = make(path, anchor=FileHeadAnchor(str(anchor_path)))
    for _ in range(3):
        assert run(k)["anchor_published"] is True
    k.close()
    k.anchor.close()
    for suffix in ("", ".ledger"):
        f = str(path) + suffix
        lines = open(f).read().splitlines()
        open(f, "w").write("\n".join(lines[:-1]) + "\n")
    # Without the anchor the shorter pair is a valid pair, which is the gap.
    plain = make(path)
    assert plain.ledger_store.event_count("p") == 2
    plain.close()
    with pytest.raises(AnchorMismatch):
        make(path, anchor=FileHeadAnchor(str(anchor_path)))


def test_a_failing_anchor_does_not_undo_the_commit_but_is_recorded(tmp_path):
    class Broken:
        def publish(self, *a):
            raise OSError("anchor offline")

        def latest(self):
            return {}

    k = make(tmp_path / "a.log", anchor=Broken())
    result = run(k)
    assert result["transaction_status"] == "COMMITTED"
    assert result["anchor_published"] is False
    failed = [r for r in k.audit_logger.replay_log_history()
              if r.get("event") == "anchor_publish_failed"]
    assert failed and "anchor offline" in failed[0]["reason"]
    k.close()


def test_a_kernel_that_refuses_to_start_leaves_no_open_files(tmp_path):
    path = tmp_path / "a.log"
    k = make(path)
    for _ in range(2):
        run(k)
    k.close()
    ledger = str(path) + ".ledger"
    lines = open(ledger).read().splitlines()
    open(ledger, "w").write("\n".join(lines[:-1]) + "\n")
    with pytest.raises(LedgerAuditMismatch):
        make(path)
    os.remove(ledger)  # fine on every platform only if nothing holds it open
    os.remove(path)


# ---- Unauthenticated callers can not fill the trail --------------------------


def test_a_huge_caller_id_is_cut_in_the_record(tmp_path):
    k = make(tmp_path / "a.log")
    k.process_transaction("p", OK, "x", "X" * 1_000_000, "wrong")
    record = k.audit_logger.replay_log_history()[-1]
    assert len(record["caller_id"]) < 400
    assert "1000000 chars" in record["caller_id"]
    assert os.path.getsize(tmp_path / "a.log") < 2000
    k.close()


def test_identity_refusals_past_the_budget_are_counted_not_written(tmp_path):
    now = [0.0]
    budget = RefusalBudget(limit=5, window_seconds=60.0, clock=lambda: now[0])
    k = make(tmp_path / "a.log", refusal_budget=budget)
    for i in range(50):
        result = k.process_transaction("p", OK, "x", f"u{i}", "wrong")
        assert result["refusal_cause"] == "IDENTITY"
    assert sum(1 for r in k.audit_logger.replay_log_history()
               if r["event"] == "refused") == 5
    now[0] = 61.0
    k.process_transaction("p", OK, "x", "late", "wrong")
    records = k.audit_logger.replay_log_history()
    summary = [r for r in records if r["event"] == "refusals_suppressed"]
    assert [r["count"] for r in summary] == [45]
    k.close()


def test_pending_suppressed_count_is_written_on_close(tmp_path):
    budget = RefusalBudget(limit=1, window_seconds=3600.0)
    k = make(tmp_path / "a.log", refusal_budget=budget)
    for i in range(4):
        k.process_transaction("p", OK, "x", f"u{i}", "wrong")
    path = k.audit_logger.storage_path
    k.close()
    reopened = AuditLog(path)
    counts = [r["count"] for r in reopened.replay_log_history()
              if r["event"] == "refusals_suppressed"]
    assert counts == [3]
    reopened.close_stream()


def test_authorized_refusals_are_never_suppressed(tmp_path):
    budget = RefusalBudget(limit=1, window_seconds=3600.0)
    k = make(tmp_path / "a.log", refusal_budget=budget)
    for _ in range(5):
        run(k, text="forbidden")
    assert sum(1 for r in k.audit_logger.replay_log_history()
               if r["event"] == "refused") == 5
    k.close()


@pytest.mark.parametrize("bad", [None, 7, ["a"], {"a": 1}, b"bytes"])
def test_non_string_credentials_are_refused_not_crashed(tmp_path, bad):
    k = make(tmp_path / "a.log")
    for args in ((bad, TOKEN), (CALLER, bad)):
        result = k.process_transaction("p", OK, "x", *args)
        assert result["refusal_cause"] == "IDENTITY"
    k.close()


def test_a_non_string_partition_is_refused(tmp_path):
    k = make(tmp_path / "a.log")
    result = k.process_transaction(["p"], OK, "x", CALLER, TOKEN)
    assert result["refusal_cause"] == "IDENTITY"
    k.close()


def test_budget_rejects_nonsense_settings():
    with pytest.raises(ValueError):
        RefusalBudget(limit=0)
    with pytest.raises(ValueError):
        RefusalBudget(window_seconds=0)


# ---- Revocation and rotation -------------------------------------------------


def test_revoked_caller_is_refused_at_once(tmp_path):
    k = make(tmp_path / "a.log")
    assert run(k)["transaction_status"] == "COMMITTED"
    assert k.callers.revoke(CALLER) is True
    assert run(k)["refusal_cause"] == "IDENTITY"
    assert k.callers.revoke(CALLER) is False
    k.close()


def test_rotation_swaps_the_token_and_keeps_the_partitions(tmp_path):
    k = make(tmp_path / "a.log")
    k.callers.rotate(CALLER, "new-token-" + "n" * 40)
    assert run(k)["refusal_cause"] == "IDENTITY"
    result = k.process_transaction("q", OK, "x", CALLER, "new-token-" + "n" * 40)
    assert result["transaction_status"] == "COMMITTED"
    k.close()


def test_rotating_an_unknown_caller_is_an_error():
    from dgk import CallerRegistry
    with pytest.raises(KeyError):
        CallerRegistry().rotate("nobody", "tok")
