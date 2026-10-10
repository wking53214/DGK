"""DGK's CNS interface: what each answer means as gate verdicts.

These tests need the CNS package (`pip install -e '.[cns]'`). CI installs it.
"""

import subprocess
import sys

import pytest

cns = pytest.importorskip("cns")
from cns.gate import GateOutcome, GatePosition, resolve, unbound  # noqa: E402

from dgk import Kernel  # noqa: E402
from dgk import cns_interface as ci  # noqa: E402
from dgk.cns_interface import (  # noqa: E402
    CNSContractError,
    CNSUnavailableError,
    GovernedKernel,
    binds_submission,
    translate_result,
)

CALLER = "gov"
TOKEN = "gov-token-" + "g" * 40
OK = {
    "latency": 100.0,
    "abort_rate": 0.01,
    "reentry_rate": 0.1,
    "load_depth": 10.0,
    "determinism_index": 0.99,
}
STAGE_NAMES = [name for name, _ in ci.STAGES]


@pytest.fixture
def governed(tmp_path):
    kernel = Kernel(log_path=str(tmp_path / "audit.log"))
    kernel.callers.register(CALLER, TOKEN, ["p"])
    yield GovernedKernel(kernel)
    kernel.close()


def submit(g, telemetry=OK, text="fine", token=TOKEN, caller=CALLER, partition="p"):
    return g.submit(partition, telemetry, text, caller, token)


# ---- Commits ------------------------------------------------------------------


def test_a_commit_passes_every_alpha_stage_and_the_omega_text_check(governed):
    r = submit(governed)
    assert r.committed() and r.outcome is GateOutcome.PASS
    assert [x.gate for x in r.results] == STAGE_NAMES + [ci.TEXT_GATE]
    assert [x.position for x in r.results] == [GatePosition.ALPHA] * 5 + [GatePosition.OMEGA]
    assert all(x.outcome is GateOutcome.PASS for x in r.results)
    assert resolve(r.results) is GateOutcome.PASS


def test_text_findings_are_reported_but_do_not_block(governed):
    r = submit(governed, text="I think we believe our own ideas about this")
    assert r.committed() and r.outcome is GateOutcome.PASS
    assert "findings recorded, not blocking" in r.results[-1].reason
    assert r.transaction["compliance_anomalies"]


def test_the_kernels_own_result_is_returned_unchanged(governed):
    r = submit(governed)
    assert r.transaction["transaction_status"] == "COMMITTED"
    assert r.transaction["ledger_sequence"] == 1


# ---- Refusals -----------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs,cause,outcome,last_stage",
    [
        (dict(token="wrong"), "IDENTITY", GateOutcome.TERMINAL_BREACH, "dgk.identity"),
        (dict(telemetry=dict(OK, latency=float("nan"))), "TELEMETRY_INVALID",
         GateOutcome.RETRY, "dgk.telemetry"),
        (dict(text="this is forbidden"), "PERIMETER",
         GateOutcome.TERMINAL_BREACH, "dgk.perimeter"),
        (dict(telemetry=dict(OK, latency=900.0)), "HEALTH_LIMIT",
         GateOutcome.RETRY, "dgk.health_limit"),
    ],
)
def test_each_refusal_maps_to_its_outcome_and_stops_at_its_stage(
    governed, kwargs, cause, outcome, last_stage
):
    r = submit(governed, **kwargs)
    assert r.transaction["refusal_cause"] == cause
    assert r.outcome is outcome
    names = [x.gate for x in r.results]
    assert names == STAGE_NAMES[: STAGE_NAMES.index(last_stage) + 1]
    assert r.results[-1].outcome is outcome
    assert all(x.outcome is GateOutcome.PASS for x in r.results[:-1])
    assert all(x.position is GatePosition.ALPHA for x in r.results)
    assert r.results[-1].reason  # a refusal always says why
    assert not r.committed()


def test_the_manifest_refusal_is_a_terminal_breach(governed):
    result = {
        "transaction_status": "REJECTED",
        "refusal_cause": "MANIFEST",
        "exception_details": "Manifest contract breached: [...]",
    }
    results = translate_result(result, "p", OK, "fine", CALLER)
    assert [x.gate for x in results] == STAGE_NAMES
    assert resolve(results) is GateOutcome.TERMINAL_BREACH


def test_every_dgk_cause_has_a_stage_and_an_outcome():
    assert {cause for _, cause in ci.STAGES} == set(ci.REFUSAL_OUTCOMES)
    assert set(ci.REFUSAL_OUTCOMES.values()) <= {"RETRY", "TERMINAL_BREACH"}


def test_an_answer_the_interface_does_not_understand_fails_closed():
    for odd in ({}, {"transaction_status": "REJECTED"},
                {"transaction_status": "REJECTED", "refusal_cause": "NEW_CAUSE"},
                {"transaction_status": "MAYBE"}):
        results = translate_result(odd, "p", OK, "fine", CALLER)
        assert resolve(results) is GateOutcome.TERMINAL_BREACH
        assert results[0].gate == "dgk.unrecognized_result"


# ---- Binding ------------------------------------------------------------------


def test_every_verdict_is_bound_and_binds_the_submission(governed):
    for kwargs in ({}, dict(token="wrong"), dict(text="forbidden")):
        r = submit(governed, **kwargs)
        assert unbound(r.results) == ()
        text = kwargs.get("text", "fine")
        assert binds_submission(r.results, "p", OK, text, CALLER)


def test_a_verdict_does_not_bind_a_different_request(governed):
    r = submit(governed)
    assert not binds_submission(r.results, "p", OK, "other text", CALLER)
    assert not binds_submission(r.results, "p", dict(OK, latency=101.0), "fine", CALLER)
    assert not binds_submission(r.results, "q", OK, "fine", CALLER)
    assert not binds_submission(r.results, "p", OK, "fine", "someone-else")
    assert not binds_submission((), "p", OK, "fine", CALLER)


def test_the_token_is_never_part_of_what_a_verdict_binds(governed):
    good = submit(governed)
    bad = submit(governed, token="wrong")
    assert good.results[0].subject_digest == bad.results[0].subject_digest
    for r in (good, bad):
        for x in r.results:
            assert TOKEN not in repr(x) and "wrong" not in repr(x)


def test_the_digest_is_taken_before_the_kernel_runs(governed):
    telemetry = dict(OK)
    r = governed.submit("p", telemetry, "fine", CALLER, TOKEN)
    telemetry["latency"] = 999.0  # changed afterwards
    assert binds_submission(r.results, "p", OK, "fine", CALLER)
    assert not binds_submission(r.results, "p", telemetry, "fine", CALLER)


@pytest.mark.parametrize(
    "telemetry",
    [dict(OK, latency=float("inf")), dict(OK, latency=object()),
     dict(OK, latency=[1, 2]), {"latency": None}, dict(OK, extra={"a": [1, {"b": 2}]})],
)
def test_content_cns_cannot_bind_still_gets_a_bound_refusal_or_commit(governed, telemetry):
    r = submit(governed, telemetry=telemetry)
    assert unbound(r.results) == ()
    assert binds_submission(r.results, "p", telemetry, "fine", CALLER)


def test_a_self_referencing_telemetry_map_does_not_hang_or_crash(governed):
    loop = dict(OK)
    loop["self"] = loop
    r = submit(governed, telemetry=loop)
    assert unbound(r.results) == ()


def test_non_string_credentials_give_a_bound_terminal_breach(governed):
    r = governed.submit("p", OK, "fine", ["not", "a", "string"], TOKEN)
    assert r.outcome is GateOutcome.TERMINAL_BREACH
    assert unbound(r.results) == ()


def test_a_huge_partition_name_keeps_the_subject_short(governed):
    r = governed.submit("P" * 100_000, OK, "fine", CALLER, TOKEN)
    assert len(r.results[0].subject) < 400
    assert r.outcome is GateOutcome.TERMINAL_BREACH  # not a granted partition


# ---- The kernel is wrapped, not changed --------------------------------------


def test_the_wrapper_gives_the_same_decision_as_the_bare_kernel(tmp_path):
    bare = Kernel(log_path=str(tmp_path / "bare.log"))
    wrapped_kernel = Kernel(log_path=str(tmp_path / "wrapped.log"))
    for k in (bare, wrapped_kernel):
        k.callers.register(CALLER, TOKEN, ["p"])
    wrapped = GovernedKernel(wrapped_kernel)
    cases = [(OK, "fine", TOKEN), (OK, "forbidden", TOKEN), (dict(OK, latency=900.0), "x", TOKEN),
             (OK, "x", "wrong"), (dict(OK, latency=True), "x", TOKEN)]
    for telemetry, text, token in cases:
        a = bare.process_transaction("p", telemetry, text, CALLER, token)
        b = wrapped.submit("p", telemetry, text, CALLER, token).transaction
        assert a["transaction_status"] == b["transaction_status"]
        assert a.get("refusal_cause") == b.get("refusal_cause")
    bare.close()
    wrapped_kernel.close()


# ---- The contract check and the optional dependency ---------------------------


def test_a_different_cns_version_is_refused(monkeypatch, tmp_path):
    monkeypatch.setattr(cns, "__version__", "9.9.9")
    kernel = Kernel(log_path=str(tmp_path / "a.log"))
    with pytest.raises(CNSContractError, match="expected CNS 1.4.0, found 9.9.9"):
        GovernedKernel(kernel)
    kernel.close()


def test_a_missing_cns_is_a_clear_error_not_an_import_crash(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "cns", None)
    monkeypatch.setitem(sys.modules, "cns.gate", None)
    kernel = Kernel(log_path=str(tmp_path / "a.log"))
    with pytest.raises(CNSUnavailableError, match="pip install"):
        GovernedKernel(kernel)
    kernel.close()


def test_dgk_and_this_module_import_without_cns():
    code = (
        "import sys; sys.modules['cns'] = None; sys.modules['cns.gate'] = None\n"
        "import dgk, dgk.cns_interface\n"
        "print('imported')"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "imported"
