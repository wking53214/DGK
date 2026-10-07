from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Dict, List, Optional

logger = logging.getLogger("dgk.engine")

SYSTEM_NAME = "DGK Distributed Governance Control Engine"
SYSTEM_VERSION = "4.0.0"


# SYSTEM ENUMERATIONS
# ============================================================
class Regime(Enum):
    NOMINAL = auto()
    TRANSIENT_SURGE = auto()
    RESOURCE_SATURATED = auto()
    STOCHASTIC_CONFUSION = auto()
    ANOMALOUS_DRIFT = auto()
    CRITICAL_PANIC = auto()


REGIME_SEVERITY = {
    Regime.NOMINAL: 1,
    Regime.TRANSIENT_SURGE: 2,
    Regime.RESOURCE_SATURATED: 3,
    Regime.STOCHASTIC_CONFUSION: 4,
    Regime.ANOMALOUS_DRIFT: 5,
    Regime.CRITICAL_PANIC: 6,
}


# ============================================================
# STRUCTURAL DATA CONFIGURATIONS
# ============================================================
@dataclass(frozen=True)
class TelemetryLimits:
    MAX_LATENCY_MS: float = 600.0
    MAX_ABORT_RATE: float = 1.0
    MAX_REENTRY_RATE: float = 10.0
    MAX_LOAD_DEPTH: float = 5000.0
    MIN_DETERMINISM: float = 0.0
    MAX_DETERMINISM: float = 1.0


@dataclass(frozen=True)
class EnergyWeights:
    weight_latency: float = 0.20
    weight_abort: float = 0.30
    weight_reentry: float = 0.20
    weight_load: float = 0.15
    weight_determinism: float = 0.15


@dataclass(frozen=True)
class TelemetryReading:
    latency: float
    abort_rate: float
    reentry_rate: float
    load_depth: float
    determinism_index: float


@dataclass(frozen=True)
class Provenance:
    actor_id: str
    policy_id: str
    justification: str


@dataclass(frozen=True)
class Event:
    event_id: str
    entity_id: str
    sequence_no: int
    event_type: str
    delta: Dict[str, Any]
    provenance: Provenance


@dataclass(frozen=True)
class Snapshot:
    entity_id: str
    last_sequence_no: int
    context: Dict[str, Any]


@dataclass(frozen=True)
class CheckResult:
    passed: bool
    rule_identifier: str
    details: Optional[str] = None


@dataclass
class RequestContext:
    request_text: str
    raw_request: Dict[str, Any]
    messages: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    audit_enabled: bool = True


# ============================================================
