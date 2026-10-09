"""Telemetry is validated at the door.

A NaN used to be committed and corrupted the classifier for the life of the process.
An infinity or a large negative raised out of process_transaction before any refusal
was recorded. A small negative (a latency of -600) passed the health limit.
Every case now ends in a recorded REJECTED with cause TELEMETRY_INVALID.
"""

import json
import math
from pathlib import Path

import pytest

from dgk import Kernel

CALLER = "tester"
TOKEN = "tester-token-0123456789abcdef0123456789"
CALM = {
    "latency": 100.0,
    "abort_rate": 0.01,
    "reentry_rate": 0.1,
    "load_depth": 100.0,
    "determinism_index": 0.99,
}
FIELDS = list(CALM)


@pytest.fixture
def kernel(tmp_path):
    k = Kernel(log_path=str(tmp_path / "audit.log"))
    k.callers.register(CALLER, TOKEN, ["p"])
    return k


def run(kernel, telemetry):
    return kernel.process_transaction("p", telemetry, "fine", caller_id=CALLER, caller_token=TOKEN)


def records(kernel):
    text = Path(kernel.audit_logger.storage_path).read_text()
    return [json.loads(line) for line in text.splitlines() if line]


BAD = [math.nan, math.inf, -math.inf, -0.001, -601.0, -1e9]


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("value", BAD, ids=repr)
def test_bad_value_is_refused_and_recorded(kernel, field, value):
    result = run(kernel, {**CALM, field: value})
    assert result["transaction_status"] == "REJECTED"
    refusals = [r for r in records(kernel) if r.get("event") == "refused"]
    assert [r["cause"] for r in refusals] == ["TELEMETRY_INVALID"]
    assert field in refusals[0]["reason"]
    assert kernel.ledger_store.get_events_since("p", 0) == []


@pytest.mark.parametrize("value", ["abc", None, [1], {"a": 1}, "1e999999"], ids=repr)
def test_non_numeric_value_is_refused_not_raised(kernel, value):
    result = run(kernel, {**CALM, "latency": value})
    assert result["transaction_status"] == "REJECTED"
    assert [r["cause"] for r in records(kernel)] == ["TELEMETRY_INVALID"]


def test_a_refused_nan_does_not_corrupt_later_classification(kernel, tmp_path):
    run(kernel, {**CALM, "latency": math.nan})
    clean = Kernel(log_path=str(tmp_path / "clean.log"))
    clean.callers.register(CALLER, TOKEN, ["p"])
    after = run(kernel, CALM)["stability_profile"]
    reference = run(clean, CALM)["stability_profile"]
    assert math.isfinite(after["lyapunov_energy"])
    assert after == reference


def test_missing_fields_still_default(kernel):
    assert run(kernel, {})["transaction_status"] == "COMMITTED"


def test_boundary_values_are_still_accepted(kernel):
    assert run(kernel, {**CALM, "latency": 0.0, "abort_rate": 0.0})["transaction_status"] == "COMMITTED"
    assert run(kernel, {**CALM, "latency": 500.0})["transaction_status"] == "COMMITTED"


def test_health_limit_still_blocks_a_real_breach(kernel):
    result = run(kernel, {**CALM, "latency": 501.0})
    assert result["transaction_status"] == "REJECTED"
    assert [r["cause"] for r in records(kernel)] == ["HEALTH_LIMIT"]


def test_unauthorized_caller_is_still_refused_first(kernel):
    result = kernel.process_transaction("p", {**CALM, "latency": math.nan}, "x",
                                        caller_id=CALLER, caller_token="wrong")
    assert result["transaction_status"] == "REJECTED"
    assert [r["cause"] for r in records(kernel)] == ["IDENTITY"]


def test_health_limit_check_fails_closed_on_non_finite_even_if_called_directly():
    from dgk.interceptors import HealthLimitCheck
    from dgk.taxonomy import TelemetryReading

    for field in ("latency", "abort_rate", "reentry_rate"):
        reading = TelemetryReading(**{**CALM, field: math.nan})
        ok, faults = HealthLimitCheck().verify_bounds(reading)
        assert not ok and faults, field
