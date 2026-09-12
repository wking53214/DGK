from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dgk.engine")

SYSTEM_NAME = "DGK Distributed Governance Control Engine"
SYSTEM_VERSION = "4.0.0"

# SYSTEM ENUMERATIONS
# ============================================================
class OperationalRegime(Enum):
    NOMINAL = auto()
    TRANSIENT_SURGE = auto()
    RESOURCE_SATURATED = auto()
    STOCHASTIC_CONFUSION = auto()
    ANOMALOUS_DRIFT = auto()
    CRITICAL_PANIC = auto()


REGIME_SEVERITY_INDEX = {
    OperationalRegime.NOMINAL: 1,
    OperationalRegime.TRANSIENT_SURGE: 2,
    OperationalRegime.RESOURCE_SATURATED: 3,
    OperationalRegime.STOCHASTIC_CONFUSION: 4,
    OperationalRegime.ANOMALOUS_DRIFT: 5,
    OperationalRegime.CRITICAL_PANIC: 6,
}

# ============================================================
# STRUCTURAL DATA CONFIGURATIONS
# ============================================================
@dataclass(frozen=True)
class TelemetryCeilings:
    MAX_LATENCY_MS: float = 600.0
    MAX_ABORT_RATE: float = 1.0
    MAX_REENTRY_RATE: float = 10.0
    MAX_LOAD_DEPTH: float = 5000.0
    MIN_DETERMINISM: float = 0.0
    MAX_DETERMINISM: float = 1.0


@dataclass(frozen=True)
class LyapunovWeightConfig:
    weight_latency: float = 0.20
    weight_abort: float = 0.30
    weight_reentry: float = 0.20
    weight_load: float = 0.15
    weight_determinism: float = 0.15


@dataclass(frozen=True)
class TelemetryMetricsPayload:
    latency: float
    abort_rate: float
    reentry_rate: float
    load_depth: float
    determinism_index: float


@dataclass(frozen=True)
class OperationProvenance:
    actor_id: str
    policy_id: str
    justification: str


@dataclass(frozen=True)
class NormalizedEvent:
    event_id: str
    entity_id: str
    sequence_no: int
    event_type: str
    delta: Dict[str, Any]
    provenance: OperationProvenance


@dataclass(frozen=True)
class StateSnapshot:
    entity_id: str
    last_sequence_no: int
    context: Dict[str, Any]


@dataclass(frozen=True)
class RuleResult:
    passed: bool
    rule_identifier: str
    details: Optional[str] = None


@dataclass
class GovernanceContext:
    request_text: str
    raw_request: Dict[str, Any]
    messages: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    audit_enabled: bool = True

# ============================================================
