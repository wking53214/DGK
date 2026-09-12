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
    REGIME_SEVERITY_INDEX,
    SYSTEM_NAME,
    SYSTEM_VERSION,
    GovernanceContext,
    LyapunovWeightConfig,
    NormalizedEvent,
    OperationProvenance,
    OperationalRegime,
    RuleResult,
    StateSnapshot,
    TelemetryCeilings,
    TelemetryMetricsPayload,
)
from .serialization import (
    canonicalize_dictionary,
    filter_private_keys,
    normalize_numeric_precision,
)
from .audit import (
    AuditTrailWAL,
    generate_hmac_signature,
    verify_hmac_signature,
)
from .ledger import (
    CheckpointPolicy,
    CryptographicHashChainStrategy,
    CoreGovernanceReducer,
    MaterializationRuntime,
    PartitionedEventStore,
    StateStreamReducer,
    StateTransitionAuditor,
    SHA256EventChaining,
    UniformIntervalSnapshotPolicy,
    ValidationManifest,
    verify_critical_escalation_constraint,
)
from .linguistics import LanguageNormalizer, LinguisticComplianceValidator
from .stability import (
    ControlTheoryRegimeClassifier,
    EchoStateReservoir,
    HysteresisControlChassis,
    RunningWelfordStatistics,
    ThreadSafeSystemAnalytics,
    calculate_lyapunov_state_energy,
    calculate_shannon_entropy,
)
from .interceptors import (
    ContentFilterInterceptor,
    Interceptor,
    InterceptorRegistry,
    RequestNormalizer,
    RuntimeBoundaryBarrier,
)
from .kernel import GovernanceOrchestrationKernel

__all__ = [
    "SYSTEM_NAME", "SYSTEM_VERSION",
    "OperationalRegime", "REGIME_SEVERITY_INDEX", "TelemetryCeilings",
    "LyapunovWeightConfig", "TelemetryMetricsPayload", "OperationProvenance",
    "NormalizedEvent", "StateSnapshot", "RuleResult", "GovernanceContext",
    "canonicalize_dictionary", "normalize_numeric_precision", "filter_private_keys",
    "AuditTrailWAL", "generate_hmac_signature", "verify_hmac_signature",
    "CryptographicHashChainStrategy",
    "PartitionedEventStore", "StateStreamReducer", "CoreGovernanceReducer",
    "ValidationManifest", "verify_critical_escalation_constraint",
    "StateTransitionAuditor", "CheckpointPolicy", "UniformIntervalSnapshotPolicy",
    "SHA256EventChaining",
    "MaterializationRuntime",
    "LinguisticComplianceValidator", "LanguageNormalizer",
    "RunningWelfordStatistics", "ThreadSafeSystemAnalytics",
    "calculate_shannon_entropy", "calculate_lyapunov_state_energy",
    "ControlTheoryRegimeClassifier", "HysteresisControlChassis",
    "EchoStateReservoir",
    "Interceptor", "InterceptorRegistry", "RequestNormalizer",
    "ContentFilterInterceptor", "RuntimeBoundaryBarrier",
    "GovernanceOrchestrationKernel",
]
