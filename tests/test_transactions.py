import os
import tempfile
import threading

from dgk import Kernel

OK_TELEMETRY = {
    "latency": 134.2,
    "abort_rate": 0.008,
    "reentry_rate": 0.04,
    "load_depth": 280.0,
    "determinism_index": 0.998,
}


def test_concurrent_transactions_keep_sequence_and_audit_consistent():
    log = os.path.join(tempfile.mkdtemp(), "audit.log")
    kernel = Kernel(log_path=log)

    def worker():
        for _ in range(25):
            kernel.process_transaction("p", dict(OK_TELEMETRY), "plain text")

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    numbers = sorted(
        e.sequence_no for e in kernel.ledger_store.get_events_since("p", 0)
    )
    assert numbers == list(range(1, 6 * 25 + 1))
    with open(log) as fh:
        assert sum(1 for line in fh if line.strip()) == 6 * 25
