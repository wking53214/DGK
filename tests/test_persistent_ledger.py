import json
import os
import stat
import tempfile

import pytest

from dgk.ledger import EventStore
from dgk.taxonomy import Provenance

PROV = Provenance(actor_id="a", policy_id="p", justification="j")


def fresh():
    return os.path.join(tempfile.mkdtemp(), "ledger.jsonl")


def fill(path, n=3, entity="p"):
    store = EventStore(path=path)
    for i in range(n):
        store.append_event(entity, "telemetry_update", {"latency": float(i)}, PROV)
    store.close()


def test_events_survive_a_restart_and_the_chain_verifies():
    path = fresh()
    fill(path)
    store = EventStore(path=path)
    assert len(store.get_events_since("p", 0)) == 3
    assert store.verify_chain("p") is True
    store.append_event("p", "telemetry_update", {}, PROV)
    assert store.get_events_since("p", 0)[-1].sequence_no == 4
    store.close()


def test_ledger_file_is_owner_only():
    path = fresh()
    fill(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_edited_event_is_refused_on_load():
    path = fresh()
    fill(path)
    lines = open(path).read().splitlines()
    record = json.loads(lines[1])
    record["delta"]["latency"] = 999.0
    lines[1] = json.dumps(record, sort_keys=True)
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        EventStore(path=path)


def test_deleted_middle_event_is_refused_on_load():
    path = fresh()
    fill(path)
    lines = open(path).read().splitlines()
    del lines[1]
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        EventStore(path=path)


def test_unserializable_delta_changes_nothing():
    path = fresh()
    store = EventStore(path=path)
    with pytest.raises(TypeError):
        store.append_event("p", "telemetry_update", {"bad": object()}, PROV)
    assert store.get_events_since("p", 0) == []
    store.close()
    assert open(path).read() == ""


def test_memory_only_store_writes_no_file(tmp_path):
    store = EventStore()
    store.append_event("p", "telemetry_update", {}, PROV)
    assert store.verify_chain("p") is True
    assert list(tmp_path.iterdir()) == []


@pytest.mark.xfail(
    strict=True,
    reason="removing the newest events is not detectable without an external anchor",
)
def test_truncating_the_newest_event_is_detected():
    path = fresh()
    fill(path)
    lines = open(path).read().splitlines()
    open(path, "w").write("\n".join(lines[:-1]) + "\n")
    with pytest.raises(ValueError):
        EventStore(path=path)


def test_a_restarted_kernel_loads_its_earlier_ledger():
    from dgk import Kernel

    log = os.path.join(tempfile.mkdtemp(), "audit.log")
    first = Kernel(log_path=log)
    first.callers.register("c", "tok-0123456789abcdef0123456789", ["p"])
    telemetry = {"latency": 10.0, "abort_rate": 0.0, "reentry_rate": 0.0}
    first.process_transaction(
        "p", telemetry, "fine", "c", "tok-0123456789abcdef0123456789"
    )
    first.ledger_store.close()
    second = Kernel(log_path=log)
    assert len(second.ledger_store.get_events_since("p", 0)) == 1
    assert second.ledger_store.verify_chain("p") is True
    second.ledger_store.close()
