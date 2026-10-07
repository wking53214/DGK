from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from .audit import AuditLog
from .interceptors import (
    ForbiddenWordRule,
    RuleRegistry,
    RequestBuilder,
    HealthLimitCheck,
)
from .ledger import (
    StateReducer,
    StateMaterializer,
    EventStore,
    TransitionChecker,
    InvariantSet,
    check_escalation_invariant,
)
from .linguistics import TextNormalizer, TextChecker
from .stability import RegimeTracker
from .taxonomy import Provenance, TelemetryReading


# GOVERNANCE CENTRAL KERNEL CONCURRENCY ENGINE
# ============================================================
class Kernel:
    """Consolidates interceptors, block stores, and stability planes into a single source of truth."""

    def __init__(self, log_path: Optional[str] = None) -> None:
        # No shared default: the old /tmp/gov4_central_ssot.log was readable
        # and pre-creatable by any local user. The caller (or DGK_AUDIT_LOG)
        # must choose where the audit trail lives.
        log_path = log_path or os.environ.get("DGK_AUDIT_LOG")
        if not log_path:
            raise ValueError("pass log_path= or set DGK_AUDIT_LOG")
        self.audit_logger = AuditLog(log_path)
        self.ledger_store = EventStore()
        self.state_reducer = StateReducer()
        self.materialization_runtime = StateMaterializer(
            self.ledger_store, self.state_reducer
        )
        self.linguistic_compliance_engine = TextChecker()
        self.text_normalizer = TextNormalizer()
        self.hysteresis_chassis = RegimeTracker()

        self.interceptor_registry = RuleRegistry()
        self.interceptor_registry.register(ForbiddenWordRule())
        self.boundary_barrier = HealthLimitCheck()

        core_validation_manifest = InvariantSet(
            manifest_id="CENTRAL_ORCHESTRATION_MANIFEST",
            manifest_version="v1.0",
            invariants={"check_escalation_invariant": check_escalation_invariant},
        )
        self.transition_auditor = TransitionChecker(
            core_validation_manifest, self.state_reducer
        )

    def process_transaction(
        self, partition_id: str, telemetry_map: Dict[str, Any], text_payload: str
    ) -> Dict[str, Any]:
        # 1. Control-Theory Telemetry Profile Processing
        telemetry = TelemetryReading(
            latency=float(telemetry_map.get("latency", 0.0)),
            abort_rate=float(telemetry_map.get("abort_rate", 0.0)),
            reentry_rate=float(telemetry_map.get("reentry_rate", 0.0)),
            load_depth=float(telemetry_map.get("load_depth", 0.0)),
            determinism_index=float(telemetry_map.get("determinism_index", 1.0)),
        )
        stability_metrics = self.hysteresis_chassis.process_telemetry_step(telemetry)
        boundary_pass, boundary_faults = self.boundary_barrier.verify_bounds(telemetry)

        # 2. Structural Rule Pipeline Routing
        normalized_payload = {
            "text": text_payload,
            "messages": [{"role": "user", "content": text_payload}],
        }
        governance_context = RequestBuilder.normalize(normalized_payload)
        perimeter_check = self.interceptor_registry.evaluate(governance_context)

        if not perimeter_check.passed:
            return {
                "transaction_status": "REJECTED",
                "exception_details": perimeter_check.details,
                "telemetry_metrics": stability_metrics,
            }

        # 3. Cryptographic Block Evaluation & Manifest Verification
        active_state_view = dict(
            self.materialization_runtime.materialize_state(partition_id)
        )
        provenance_block = Provenance(
            actor_id="orchestration_kernel_core",
            policy_id="CENTRAL_ORCHESTRATION_MANIFEST",
            justification="Automated ingestion block commit",
        )

        simulation_store = EventStore()
        simulated_event, _ = simulation_store.append_event(
            partition_id, "telemetry_update", telemetry_map, provenance_block
        )
        transition_verified, invariant_breaches = (
            self.transition_auditor.verify_transition(
                active_state_view, simulated_event
            )
        )

        if not transition_verified:
            return {
                "transaction_status": "REJECTED",
                "exception_details": f"Manifest contract breached: {invariant_breaches}",
            }

        # Commit permanent record entry blocks down to the ledger partition upon validation pass
        committed_block, blockchain_head_hash = self.ledger_store.append_event(
            partition_id, "telemetry_update", telemetry_map, provenance_block
        )

        # 4. Text Verification & Language Compliance Normalization
        linguistic_anomalies = self.linguistic_compliance_engine.validate_text_stream(
            text_payload
        )
        scrubbed_text_output = self.text_normalizer.normalize(text_payload)

        # 5. Emit structural state execution fields to the Write-Ahead Log
        self.audit_logger.append_record(
            {
                "partition_id": partition_id,
                "timestamp": time.time(),
                "blockchain_hash_head": blockchain_head_hash,
                "stream_sequence_index": committed_block.sequence_no,
                "operational_regime": stability_metrics["operational_regime"],
                "boundary_pass": boundary_pass,
                "boundary_faults": boundary_faults,
                "linguistic_anomalies": linguistic_anomalies,
            }
        )

        return {
            "transaction_status": "COMMITTED" if boundary_pass else "WARNING_FLAGGED",
            "scrubbed_text": scrubbed_text_output,
            "compliance_anomalies": linguistic_anomalies,
            "stability_profile": stability_metrics,
            "ledger_sequence": committed_block.sequence_no,
            "block_hash": blockchain_head_hash,
        }


# ============================================================
