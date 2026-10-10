"""Adversarial checks against the guarantees DGK claims.

Each test states a guarantee and tries to break it. A test marked xfail is a
confirmed gap: the guarantee does not hold today, and the reason says why. A
gap closes when its xfail marker is removed and the test passes.
"""

import json
import os
import threading
from pathlib import Path

import pytest

from dgk import (
    AuditLog,
    EventStore,
    Kernel,
    Provenance,
    TextChecker,
    check_escalation_invariant,
    sign_record,
)

CALLER = "tester"
TOKEN = "tester-token-0123456789abcdef0123456789"
PARTITIONS = ("a", "p")


def authorize(kernel):
    kernel.callers.register(CALLER, TOKEN, PARTITIONS)
    return kernel


OK_TELEMETRY = {
    "latency": 134.2,
    "abort_rate": 0.008,
    "reentry_rate": 0.04,
    "load_depth": 280.0,
    "determinism_index": 0.998,
}
PROVENANCE = Provenance(actor_id="attacker", policy_id="none", justification="attack")


@pytest.fixture
def kernel(tmp_path):
    return authorize(Kernel(log_path=str(tmp_path / "audit.log")))


def audit_lines(kernel):
    return [
        line
        for line in Path(kernel.audit_logger.storage_path).read_text().splitlines()
        if line
    ]


# ---- Perimeter: can a forbidden request get in? -----------------------------


def test_uppercase_forbidden_word_is_rejected(kernel):
    result = kernel.process_transaction(
        "p", OK_TELEMETRY, "THIS IS FORBIDDEN", caller_id=CALLER, caller_token=TOKEN
    )
    assert result["transaction_status"] == "REJECTED"


def test_homoglyph_forbidden_word_is_rejected(kernel):
    result = kernel.process_transaction(
        "p", OK_TELEMETRY, "this is fоrbidden", caller_id=CALLER, caller_token=TOKEN
    )
    assert result["transaction_status"] == "REJECTED"


def test_punctuated_forbidden_word_is_rejected(kernel):
    result = kernel.process_transaction(
        "p", OK_TELEMETRY, "this is for-bidden", caller_id=CALLER, caller_token=TOKEN
    )
    assert result["transaction_status"] == "REJECTED"


def test_rejected_request_leaves_no_ledger_entry_and_one_refusal_line(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "forbidden", caller_id=CALLER, caller_token=TOKEN
    )
    assert kernel.ledger_store.get_events_since("p", 0) == []
    records = [json.loads(line) for line in audit_lines(kernel)]
    assert [r["event"] for r in records] == ["refused"]


def test_rejected_request_is_recorded_as_a_refusal(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "forbidden", caller_id=CALLER, caller_token=TOKEN
    )
    assert len(audit_lines(kernel)) == 1


# ---- Telemetry: can bad readings be committed? ------------------------------


def test_non_finite_telemetry_is_rejected(kernel):
    result = kernel.process_transaction(
        "p",
        dict(OK_TELEMETRY, latency=float("nan")),
        "fine",
        caller_id=CALLER,
        caller_token=TOKEN,
    )
    assert result["transaction_status"] == "REJECTED"


def test_health_breach_blocks_the_commit(kernel):
    result = kernel.process_transaction(
        "p",
        dict(OK_TELEMETRY, latency=900.0),
        "fine",
        caller_id=CALLER,
        caller_token=TOKEN,
    )
    assert result["transaction_status"] != "COMMITTED"
    assert kernel.ledger_store.get_events_since("p", 0) == []


# ---- Record integrity: can history be edited without evidence? --------------


def test_audit_file_is_owner_only(kernel):
    mode = os.stat(kernel.audit_logger.storage_path).st_mode & 0o777
    assert mode == 0o600


def test_audit_file_refuses_a_planted_symlink(tmp_path):
    target = tmp_path / "victim.txt"
    target.write_text("untouched\n")
    link = tmp_path / "audit.log"
    os.symlink(target, link)
    with pytest.raises(OSError):
        AuditLog(str(link))
    assert target.read_text() == "untouched\n"


def test_editing_an_audit_line_is_detected_on_replay(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    kernel.process_transaction(
        "p", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    path = Path(kernel.audit_logger.storage_path)
    lines = path.read_text().splitlines()
    record = json.loads(lines[0])
    record["partition_id"] = "someone-else"
    lines[0] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(Exception):
        kernel.audit_logger.replay_log_history()


def test_ledger_chain_can_be_verified(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    assert hasattr(kernel.ledger_store, "verify_chain")
    assert kernel.ledger_store.verify_chain("p") is True


def test_audit_records_carry_a_signature(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    record = json.loads(audit_lines(kernel)[0])
    assert "signature" in record


def test_audit_records_name_the_caller(kernel):
    kernel.process_transaction(
        "p", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    record = json.loads(audit_lines(kernel)[0])
    assert record["caller_id"] == CALLER


# ---- Identity: can anyone write anywhere? -----------------------------------


# ---- Concurrency ------------------------------------------------------------


def test_concurrent_appends_get_unique_sequence_numbers():
    store = EventStore()

    def worker():
        for _ in range(200):
            store.append_event("p", "telemetry_update", {}, PROVENANCE)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    numbers = [e.sequence_no for e in store.get_events_since("p", 0)]
    assert sorted(numbers) == list(range(1, 8 * 200 + 1))


# ---- Invariants and text ----------------------------------------------------


def test_escalation_invariant_rejects_critical_without_an_escalation():
    before = {}
    after = {"system_status": "CRITICAL", "escalation_logged": False}
    ok, _ = check_escalation_invariant(before, None, after)
    assert ok is False


def test_sycophantic_paragraph_is_flagged():
    text = (
        "You are right about this. Absolutely correct on that point. "
        "Excellent idea overall. Great job with the structure. Brilliant work here."
    )
    assert TextChecker().validate_text_stream(text) != []


def test_partitions_do_not_see_each_others_history(kernel):
    kernel.process_transaction(
        "a", OK_TELEMETRY, "fine", caller_id=CALLER, caller_token=TOKEN
    )
    assert kernel.ledger_store.get_events_since("b", 0) == []


def test_identical_events_hash_the_same_regardless_of_key_order():
    from dgk import Event, Sha256Chain

    def make(delta):
        return Event(
            event_id="fixed-id",
            entity_id="p",
            sequence_no=1,
            event_type="telemetry_update",
            delta=delta,
            provenance=PROVENANCE,
        )

    chain = Sha256Chain()
    assert chain.compute_hash("GENESIS", make({"x": 1, "y": 2})) == chain.compute_hash(
        "GENESIS", make({"y": 2, "x": 1})
    )


def test_sign_record_is_deterministic_for_the_same_key():
    record = {"a": 1, "b": "two"}
    assert sign_record(record, b"0123456789abcdef") == sign_record(
        record, b"0123456789abcdef"
    )


# ---- Perimeter folding: more ways to hide the word ---------------------------


@pytest.mark.parametrize(
    "text",
    [
        "this is for​bidden",          # zero-width space
        "this is for­bidden",          # soft hyphen
        "this is fоrВidden",      # Cyrillic o and capital Ve (looks like B)
        "this is ｆorbidden",           # fullwidth f
        "this is for_bid.den",              # punctuation split
        "this is f o r b i d d e n",        # spaced out
    ],
)
def test_hidden_forbidden_word_is_rejected(kernel, text):
    result = kernel.process_transaction(
        "p", OK_TELEMETRY, text, caller_id=CALLER, caller_token=TOKEN
    )
    assert result["transaction_status"] == "REJECTED"
    assert result["refusal_cause"] == "PERIMETER"


@pytest.mark.parametrize(
    "text",
    ["This is allowed.", "A forbid-less sentence about bidding on a form.", "forbid"],
)
def test_ordinary_text_still_passes_the_perimeter(kernel, text):
    result = kernel.process_transaction(
        "p", OK_TELEMETRY, text, caller_id=CALLER, caller_token=TOKEN
    )
    assert result["transaction_status"] == "COMMITTED"


def test_one_flattering_marker_is_not_a_paragraph_flag():
    assert TextChecker().validate_text_stream("Great job on the report.") == []


def test_text_check_result_order_is_deterministic():
    text = (
        "I think I believe we feel. Of course, absolutely correct, brilliant, "
        "great job, you are right."
    )
    first = TextChecker().validate_text_stream(text)
    assert first == sorted(first)
    assert first == TextChecker().validate_text_stream(text)
