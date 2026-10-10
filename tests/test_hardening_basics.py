"""Small hardening fixes: booleans are not measurements, refusals name their cause."""

import pytest

from dgk import Kernel

CALLER = "basics"
TOKEN = "basics-token-" + "y" * 40
OK = {
    "latency": 100.0,
    "abort_rate": 0.0,
    "reentry_rate": 0.0,
    "load_depth": 1.0,
    "determinism_index": 1.0,
}


@pytest.fixture
def kernel(tmp_path):
    k = Kernel(log_path=str(tmp_path / "audit.log"))
    k.callers.register(CALLER, TOKEN, ["p"])
    return k


@pytest.mark.parametrize("field", list(OK))
@pytest.mark.parametrize("flag", [True, False])
def test_boolean_telemetry_is_refused(kernel, field, flag):
    result = kernel.process_transaction("p", dict(OK, **{field: flag}), "hi", CALLER, TOKEN)
    assert result["transaction_status"] == "REJECTED"
    assert result["refusal_cause"] == "TELEMETRY_INVALID"


def test_numeric_telemetry_still_commits(kernel):
    result = kernel.process_transaction("p", dict(OK, latency=1), "hi", CALLER, TOKEN)
    assert result["transaction_status"] == "COMMITTED"
    assert "refusal_cause" not in result


@pytest.mark.parametrize(
    "telemetry,text,caller_token,cause",
    [
        (OK, "hi", "wrong", "IDENTITY"),
        (dict(OK, latency=float("nan")), "hi", TOKEN, "TELEMETRY_INVALID"),
        (OK, "this is forbidden", TOKEN, "PERIMETER"),
        (dict(OK, latency=900.0), "hi", TOKEN, "HEALTH_LIMIT"),
    ],
)
def test_the_result_names_the_same_cause_the_audit_trail_records(
    kernel, telemetry, text, caller_token, cause
):
    result = kernel.process_transaction("p", telemetry, text, CALLER, caller_token)
    assert result["refusal_cause"] == cause
    assert kernel.audit_logger.replay_log_history()[-1]["cause"] == cause
