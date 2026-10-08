import json
import os
import tempfile

import pytest

from dgk import CallerRegistry, Kernel

TOKEN = "tester-token-0123456789abcdef0123456789"
OK = {
    "latency": 134.2,
    "abort_rate": 0.008,
    "reentry_rate": 0.04,
    "load_depth": 280.0,
    "determinism_index": 0.998,
}


@pytest.fixture
def kernel():
    log = os.path.join(tempfile.mkdtemp(), "audit.log")
    k = Kernel(log_path=log)
    k.callers.register("alice", TOKEN, ["p1"])
    return k


def test_registered_caller_on_an_allowed_partition_commits(kernel):
    result = kernel.process_transaction("p1", OK, "fine", "alice", TOKEN)
    assert result["transaction_status"] == "COMMITTED"


def test_the_ledger_records_the_caller_as_actor(kernel):
    kernel.process_transaction("p1", OK, "fine", "alice", TOKEN)
    event = kernel.ledger_store.get_events_since("p1", 0)[0]
    assert event.provenance.actor_id == "alice"


def test_wrong_token_is_rejected_and_writes_nothing(kernel):
    result = kernel.process_transaction("p1", OK, "fine", "alice", "wrong")
    assert result["transaction_status"] == "REJECTED"
    assert kernel.ledger_store.get_events_since("p1", 0) == []


def test_unknown_caller_is_rejected(kernel):
    result = kernel.process_transaction("p1", OK, "fine", "mallory", TOKEN)
    assert result["transaction_status"] == "REJECTED"


def test_caller_is_rejected_on_a_partition_it_is_not_allowed(kernel):
    result = kernel.process_transaction("p2", OK, "fine", "alice", TOKEN)
    assert result["transaction_status"] == "REJECTED"
    assert kernel.ledger_store.get_events_since("p2", 0) == []


def test_empty_registry_rejects_everyone():
    log = os.path.join(tempfile.mkdtemp(), "audit.log")
    k = Kernel(log_path=log)
    result = k.process_transaction("p1", OK, "fine", "alice", TOKEN)
    assert result["transaction_status"] == "REJECTED"


def test_registry_stores_a_digest_not_the_token():
    registry = CallerRegistry()
    registry.register("alice", TOKEN, ["p1"])
    assert TOKEN not in repr(vars(registry))


def test_registration_needs_a_caller_and_a_token():
    registry = CallerRegistry()
    with pytest.raises(ValueError):
        registry.register("", TOKEN, ["p1"])
    with pytest.raises(ValueError):
        registry.register("alice", "", ["p1"])


def test_audit_line_names_the_caller(kernel):
    kernel.process_transaction("p1", OK, "fine", "alice", TOKEN)
    with open(kernel.audit_logger.storage_path) as fh:
        record = json.loads(fh.readline())
    assert record["caller_id"] == "alice"
