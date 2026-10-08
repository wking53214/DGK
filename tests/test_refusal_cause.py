"""Every refusal names its cause in the signed audit trail."""

import pytest

from dgk import Kernel

CALLER = "cause-tester"
TOKEN = "cause-token-" + "x" * 40
PARTITION = "p-cause"
OK_TELEMETRY = {
    "latency": 100.0,
    "abort_rate": 0.0,
    "reentry_rate": 0.0,
    "load_depth": 1.0,
    "determinism_index": 1.0,
}


@pytest.fixture
def kernel(tmp_path):
    k = Kernel(log_path=str(tmp_path / "audit.log"))
    k.callers.register(CALLER, TOKEN, [PARTITION])
    return k


def _refusal_causes(kernel):
    records = kernel.audit_logger.replay_log_history()
    return [r["cause"] for r in records if r.get("event") == "refused"]


def test_identity_refusal_is_recorded_as_identity(kernel):
    result = kernel.process_transaction(
        PARTITION, OK_TELEMETRY, "hello", CALLER, "wrong-token"
    )
    assert result["transaction_status"] == "REJECTED"
    assert _refusal_causes(kernel) == ["IDENTITY"]


def test_perimeter_refusal_is_recorded_as_perimeter(kernel):
    kernel.process_transaction(
        PARTITION, OK_TELEMETRY, "this is forbidden", CALLER, TOKEN
    )
    assert _refusal_causes(kernel) == ["PERIMETER"]


def test_health_refusal_is_recorded_as_health_limit(kernel):
    breach = dict(OK_TELEMETRY, latency=900.0)
    kernel.process_transaction(PARTITION, breach, "hello", CALLER, TOKEN)
    assert _refusal_causes(kernel) == ["HEALTH_LIMIT"]
