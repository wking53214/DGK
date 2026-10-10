"""DGK's interface to CNS: each transaction's outcome as CNS gate verdicts.

CNS (the library's shared contract package) defines a gate with two ends: an
ALPHA end that runs before the work and an OMEGA end that runs on the result,
a verdict of PASS, RETRY or TERMINAL_BREACH, a fail-closed rule for combining
verdicts, and a digest that binds a verdict to the content it judged. DGK is
one door, and this module says what its answers mean in those terms.

DGK itself stays standard-library only. CNS is imported when it is first used
and its version is checked, so `import dgk` works without it. Install the
extra (`pip install "dgk[cns]"`) to use this module.

What this module does not do: it does not change what DGK decides, and it does
not authorize anything. DGK is a stateful door, not a pure predicate. Running a
transaction commits to the ledger and moves the regime, so there is no honest
way to ask "would you pass this?" without doing it. For that reason this module
exposes verdicts after the fact (`GovernedKernel.submit`) and not objects that
satisfy the CNS `Gate` protocol.

Which end each stage belongs to, and what each refusal means:

| Stage            | Cause              | End   | Outcome         | Why                              |
|------------------|--------------------|-------|-----------------|----------------------------------|
| identity         | IDENTITY           | ALPHA | TERMINAL_BREACH | No resubmission repairs a caller |
|                  |                    |       |                 | who is not authorized            |
| telemetry        | TELEMETRY_INVALID  | ALPHA | RETRY           | A malformed reading can be sent  |
|                  |                    |       |                 | again, correctly                 |
| perimeter        | PERIMETER          | ALPHA | TERMINAL_BREACH | DGK calls this a security        |
|                  |                    |       |                 | exception; telling a caller what |
|                  |                    |       |                 | to change would invite probing   |
| health limit     | HEALTH_LIMIT       | ALPHA | RETRY           | Conditions can recover; a new    |
|                  |                    |       |                 | reading may pass                 |
| manifest         | MANIFEST           | ALPHA | TERMINAL_BREACH | An invariant of the ledger would |
|                  |                    |       |                 | be broken                        |
| text check       | (advisory)         | OMEGA | PASS            | DGK records findings and never   |
|                  |                    |       |                 | blocks on them                   |

The RETRY and TERMINAL_BREACH assignments are a judgement, kept in one place
(`REFUSAL_OUTCOMES`) so it can be changed in one edit.

What a verdict is bound to: the request as submitted, meaning the partition,
the caller id, the telemetry as given, and the text. The caller's token is
never part of it. A verdict lifted onto a different request does not bind.
As CNS itself says, this is tamper-evidence, not tamper-proofing: there is no
secret in the digest.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Tuple

from .kernel import Kernel, _clip

#: The CNS release this interface was written against. Checked on first use.
CNS_CONTRACT_VERSION = "1.4.0"

#: DGK's refusal causes, in the order the kernel checks them, with the CNS
#: outcome each one means. Stages after the one that refused are not run.
STAGES: Tuple[Tuple[str, str], ...] = (
    ("dgk.identity", "IDENTITY"),
    ("dgk.telemetry", "TELEMETRY_INVALID"),
    ("dgk.perimeter", "PERIMETER"),
    ("dgk.health_limit", "HEALTH_LIMIT"),
    ("dgk.manifest", "MANIFEST"),
)
REFUSAL_OUTCOMES: Mapping[str, str] = {
    "IDENTITY": "TERMINAL_BREACH",
    "TELEMETRY_INVALID": "RETRY",
    "PERIMETER": "TERMINAL_BREACH",
    "HEALTH_LIMIT": "RETRY",
    "MANIFEST": "TERMINAL_BREACH",
}
TEXT_GATE = "dgk.text_check"


class CNSUnavailableError(RuntimeError):
    """CNS is not installed."""


class CNSContractError(RuntimeError):
    """CNS is installed but is not the contract this interface was written for."""


def _load_cns() -> Any:
    """Import cns.gate lazily and check it is the contract this was written for."""
    try:
        import cns
        import cns.gate as gate
    except ImportError as exc:
        raise CNSUnavailableError(
            "CNS is not installed; install it with: pip install 'dgk[cns]'"
        ) from exc
    version = getattr(cns, "__version__", None)
    if version != CNS_CONTRACT_VERSION:
        raise CNSContractError(
            f"expected CNS {CNS_CONTRACT_VERSION}, found {version}"
        )
    needed = {
        "GateResult": ("gate", "position", "outcome", "reason", "subject", "subject_digest"),
    }
    for name, fields in needed.items():
        have = getattr(getattr(gate, name, None), "__dataclass_fields__", {})
        missing = [f for f in fields if f not in have]
        if missing:
            raise CNSContractError(f"cns.gate.{name} is missing fields: {missing}")
    for enum_name, members in (
        ("GatePosition", ("ALPHA", "OMEGA")),
        ("GateOutcome", ("PASS", "RETRY", "TERMINAL_BREACH")),
    ):
        enum = getattr(gate, enum_name, None)
        if enum is None or any(not hasattr(enum, m) for m in members):
            raise CNSContractError(f"cns.gate.{enum_name} does not have {members}")
    return gate


_MAX_DEPTH = 16


def _bindable(value: Any, depth: int = 0) -> Any:
    """Describe submitted content in the types a CNS digest accepts.

    CNS refuses NaN, infinities and unknown types, because a verdict cannot be
    bound to them. DGK still refuses such requests and must still be able to
    say so, so they are bound as text that names what was submitted.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else f"<float {value!r}>"
    if depth >= _MAX_DEPTH:
        return "<too deep>"
    if isinstance(value, Mapping):
        return {str(k): _bindable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bindable(v, depth + 1) for v in value]
    return f"<{type(value).__name__}>"


def submission_content(
    partition_id: Any,
    telemetry_map: Any,
    text_payload: Any,
    caller_id: Any,
) -> Dict[str, Any]:
    """What a verdict is bound to. The caller's token is deliberately absent."""
    return {
        "partition_id": _bindable(partition_id),
        "caller_id": _bindable(caller_id),
        "telemetry": _bindable(telemetry_map),
        "text": _bindable(text_payload),
    }


def submission_subject(partition_id: Any) -> str:
    return f"dgk:{_clip(partition_id)}"


def submission_digest(
    partition_id: Any, telemetry_map: Any, text_payload: Any, caller_id: Any
) -> str:
    """The CNS digest of a submission, computed the way every consumer does."""
    return _load_cns().subject_digest(
        submission_content(partition_id, telemetry_map, text_payload, caller_id)
    )


def translate_result(
    transaction: Mapping[str, Any],
    partition_id: Any,
    telemetry_map: Any,
    text_payload: Any,
    caller_id: Any,
) -> Tuple[Any, ...]:
    """Turn one DGK transaction result into CNS gate verdicts.

    A refusal gives a PASS for every stage before the one that refused and the
    refusal itself; stages after it never ran and are not reported. A commit
    gives a PASS for every ALPHA stage and an OMEGA text-check verdict.
    """
    digest = submission_digest(partition_id, telemetry_map, text_payload, caller_id)
    return _translate(transaction, submission_subject(partition_id), digest)


def _translate(
    transaction: Mapping[str, Any], subject: str, digest: str
) -> Tuple[Any, ...]:
    gate = _load_cns()

    def verdict(name, position, outcome, reason):
        return gate.GateResult(
            gate=name,
            position=position,
            outcome=outcome,
            reason=reason,
            subject=subject,
            subject_digest=digest,
        )

    alpha, omega = gate.GatePosition.ALPHA, gate.GatePosition.OMEGA
    passed = gate.GateOutcome.PASS
    results = []
    status = transaction.get("transaction_status")
    if status == "COMMITTED":
        results = [verdict(name, alpha, passed, "passed") for name, _ in STAGES]
        anomalies = list(transaction.get("compliance_anomalies") or [])
        reason = (
            "findings recorded, not blocking: " + ", ".join(anomalies)
            if anomalies
            else "no findings"
        )
        results.append(verdict(TEXT_GATE, omega, passed, reason))
        return tuple(results)

    cause = transaction.get("refusal_cause")
    if status != "REJECTED" or cause not in REFUSAL_OUTCOMES:
        # Fail closed: an answer this interface does not understand is a breach.
        return (
            verdict(
                "dgk.unrecognized_result",
                alpha,
                gate.GateOutcome.TERMINAL_BREACH,
                f"unrecognized DGK result: status={status!r} cause={cause!r}",
            ),
        )
    for name, stage_cause in STAGES:
        if stage_cause == cause:
            outcome = getattr(gate.GateOutcome, REFUSAL_OUTCOMES[cause])
            results.append(
                verdict(name, alpha, outcome, _clip(transaction.get("exception_details", "")))
            )
            break
        results.append(verdict(name, alpha, passed, "passed"))
    return tuple(results)


def binds_submission(
    results: Tuple[Any, ...],
    partition_id: Any,
    telemetry_map: Any,
    text_payload: Any,
    caller_id: Any,
) -> bool:
    """Whether every verdict was issued against exactly this submission."""
    subject = submission_subject(partition_id)
    digest = submission_digest(partition_id, telemetry_map, text_payload, caller_id)
    return bool(results) and all(r.binds(subject, digest) for r in results)


@dataclass(frozen=True)
class GovernedResult:
    """One transaction: DGK's own answer, and what it means in CNS terms."""

    outcome: Any  # cns.gate.GateOutcome
    results: Tuple[Any, ...]  # cns.gate.GateResult, in the order the stages ran
    transaction: Dict[str, Any]  # DGK's result, unchanged

    def committed(self) -> bool:
        return self.transaction.get("transaction_status") == "COMMITTED"


class GovernedKernel:
    """A DGK kernel that reports every answer as CNS gate verdicts.

    Wraps a kernel; does not replace it or change what it decides. The token
    passes straight through to the kernel and is never copied into a verdict.
    """

    def __init__(self, kernel: Kernel) -> None:
        self.kernel = kernel
        _load_cns()  # fail at construction, not on the first request

    def submit(
        self,
        partition_id: str,
        telemetry_map: Dict[str, Any],
        text_payload: str,
        caller_id: str,
        caller_token: str,
    ) -> GovernedResult:
        # Bound before the kernel runs, so a caller who changes the dict
        # afterwards cannot make the verdict describe something else.
        subject = submission_subject(partition_id)
        digest = submission_digest(partition_id, telemetry_map, text_payload, caller_id)
        transaction = self.kernel.process_transaction(
            partition_id, telemetry_map, text_payload, caller_id, caller_token
        )
        results = _translate(transaction, subject, digest)
        return GovernedResult(_load_cns().resolve(results), results, transaction)
