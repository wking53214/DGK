"""
DGK -- Distributed Governance Control Engine.

A governance kernel for systems that must be able to prove, afterwards, what
they did and why. Every accepted operation lands in an append-only ledger whose
entries are chained by SHA-256 and signed with HMAC, so a later edit to the
record is detectable rather than merely discouraged.

A transaction runs through five stages, and any of the first three can stop it:

  1. Telemetry is classified into an operational regime, with hysteresis so a
     system on a threshold does not oscillate between regimes  (stability.py)
  2. Perimeter interceptors accept or reject the request, failing
     closed and naming the rule that rejected it              (interceptors.py)
  3. The proposed state transition is checked against a validation manifest of
     invariants before anything is committed                       (ledger.py)
  4. The event is appended to a partitioned, hash-chained store and the
     projected state is rebuilt from it                            (ledger.py)
  5. Text is checked for compliance and normalized            (linguistics.py)

Then the whole outcome is written to a write-ahead audit log        (audit.py)

The design position worth naming: state is *derived*, never stored directly.
Current state is a replay of the event stream, so the ledger is the single
source of truth and a state value that disagrees with the events that produced
it is a detectable contradiction rather than an invisible one.

This package is a reconstruction; see PROVENANCE.md and RECONSTRUCTION.md.
"""

from .taxonomy import (
    REGIME_SEVERITY,
    SYSTEM_NAME,
    SYSTEM_VERSION,
    RequestContext,
    EnergyWeights,
    Event,
    Provenance,
    Regime,
    CheckResult,
    Snapshot,
    TelemetryLimits,
    TelemetryReading,
)
from .serialization import (
    to_canonical_json,
    drop_private_fields,
    round_floats,
)
from .audit import (
    AuditLog,
    sign_record,
    verify_record,
)
from .ledger import (
    SnapshotPolicy,
    HashChainStrategy,
    StateReducer,
    StateMaterializer,
    EventStore,
    Reducer,
    TransitionChecker,
    Sha256Chain,
    EveryNEventsPolicy,
    InvariantSet,
    check_escalation_invariant,
)
from .linguistics import TextNormalizer, TextChecker
from .stability import (
    RegimeClassifier,
    Reservoir,
    RegimeTracker,
    RunningStats,
    ThreadSafeStats,
    calculate_deviation_score,
    calculate_entropy,
)
from .interceptors import (
    ForbiddenWordRule,
    Rule,
    RuleRegistry,
    RequestBuilder,
    HealthLimitCheck,
)
from .identity import CallerRegistry
from .anchor import AnchorMismatch, FileHeadAnchor, HeadAnchor
from .budget import RefusalBudget
from .kernel import Kernel, LedgerAuditMismatch, TelemetryError

__all__ = [
    "SYSTEM_NAME",
    "SYSTEM_VERSION",
    "Regime",
    "REGIME_SEVERITY",
    "TelemetryLimits",
    "EnergyWeights",
    "TelemetryReading",
    "Provenance",
    "Event",
    "Snapshot",
    "CheckResult",
    "RequestContext",
    "to_canonical_json",
    "round_floats",
    "drop_private_fields",
    "AuditLog",
    "sign_record",
    "verify_record",
    "HashChainStrategy",
    "EventStore",
    "Reducer",
    "StateReducer",
    "InvariantSet",
    "check_escalation_invariant",
    "TransitionChecker",
    "SnapshotPolicy",
    "EveryNEventsPolicy",
    "Sha256Chain",
    "StateMaterializer",
    "TextChecker",
    "TextNormalizer",
    "RunningStats",
    "ThreadSafeStats",
    "calculate_entropy",
    "calculate_deviation_score",
    "RegimeClassifier",
    "RegimeTracker",
    "Reservoir",
    "Rule",
    "RuleRegistry",
    "CallerRegistry",
    "RequestBuilder",
    "ForbiddenWordRule",
    "HealthLimitCheck",
    "Kernel",
    "LedgerAuditMismatch",
    "TelemetryError",
    "AnchorMismatch",
    "FileHeadAnchor",
    "HeadAnchor",
    "RefusalBudget",
]
