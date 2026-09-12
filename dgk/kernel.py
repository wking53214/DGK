from __future__ import annotations

import time
from typing import Any, Dict

from .audit import AuditTrailWAL
from .interceptors import ContentFilterInterceptor, InterceptorRegistry, RequestNormalizer, RuntimeBoundaryBarrier
from .ledger import (
    CoreGovernanceReducer,
    MaterializationRuntime,
    PartitionedEventStore,
    StateTransitionAuditor,
    ValidationManifest,
    verify_critical_escalation_constraint,
)
from .linguistics import LanguageNormalizer, LinguisticComplianceValidator
from .stability import HysteresisControlChassis
from .taxonomy import OperationProvenance, TelemetryMetricsPayload

# GOVERNANCE CENTRAL KERNEL CONCURRENCY ENGINE
# ============================================================
class GovernanceOrchestrationKernel:
    """Consolidates interceptors, block stores, and stability planes into a single source of truth."""
    def __init__(self, log_path: str = "/tmp/gov4_central_ssot.log") -> None:
        self.audit_logger = AuditTrailWAL(log_path)
        self.ledger_store = PartitionedEventStore()
        self.state_reducer = CoreGovernanceReducer()
        self.materialization_runtime = MaterializationRuntime(self.ledger_store, self.state_reducer)
        self.linguistic_compliance_engine = LinguisticComplianceValidator()
        self.text_normalizer = LanguageNormalizer()
        self.hysteresis_chassis = HysteresisControlChassis()
        
        self.interceptor_registry = InterceptorRegistry()
        self.interceptor_registry.register(ContentFilterInterceptor())
        self.boundary_barrier = RuntimeBoundaryBarrier()
        
        core_validation_manifest = ValidationManifest(
            manifest_id="CENTRAL_ORCHESTRATION_MANIFEST", manifest_version="v1.0",
            invariants={"verify_critical_escalation_constraint": verify_critical_escalation_constraint}
        )
        self.transition_auditor = StateTransitionAuditor(core_validation_manifest, self.state_reducer)

    def process_transaction(self, partition_id: str, telemetry_map: Dict[str, Any], text_payload: str) -> Dict[str, Any]:
        # 1. Control-Theory Telemetry Profile Processing
        telemetry = TelemetryMetricsPayload(
            latency=float(telemetry_map.get("latency", 0.0)),
            abort_rate=float(telemetry_map.get("abort_rate", 0.0)),
            reentry_rate=float(telemetry_map.get("reentry_rate", 0.0)),
            load_depth=float(telemetry_map.get("load_depth", 0.0)),
            determinism_index=float(telemetry_map.get("determinism_index", 1.0))
        )
        stability_metrics = self.hysteresis_chassis.process_telemetry_step(telemetry)
        boundary_pass, boundary_faults = self.boundary_barrier.verify_bounds(telemetry)

        # 2. Structural Interceptor Pipeline Routing
        normalized_payload = {"text": text_payload, "messages": [{"role": "user", "content": text_payload}]}
        governance_context = RequestNormalizer.normalize(normalized_payload)
        perimeter_check = self.interceptor_registry.evaluate(governance_context)

        if not perimeter_check.passed:
            return {"transaction_status": "REJECTED", "exception_details": perimeter_check.details, "telemetry_metrics": stability_metrics}

        # 3. Cryptographic Block Evaluation & Manifest Verification
        active_state_view = dict(self.materialization_runtime.materialize_state(partition_id))
        provenance_block = OperationProvenance(
            actor_id="orchestration_kernel_core", policy_id="CENTRAL_ORCHESTRATION_MANIFEST", justification="Automated ingestion block commit"
        )
        
        simulation_store = PartitionedEventStore()
        simulated_event, _ = simulation_store.append_event(partition_id, "telemetry_update", telemetry_map, provenance_block)
        transition_verified, invariant_breaches = self.transition_auditor.verify_transition(active_state_view, simulated_event)

        if not transition_verified:
            return {"transaction_status": "REJECTED", "exception_details": f"Manifest contract breached: {invariant_breaches}"}

        # Commit permanent record entry blocks down to the ledger partition upon validation pass
        committed_block, blockchain_head_hash = self.ledger_store.append_event(partition_id, "telemetry_update", telemetry_map, provenance_block)

        # 4. Text Verification & Language Compliance Normalization
        linguistic_anomalies = self.linguistic_compliance_engine.validate_text_stream(text_payload)
        scrubbed_text_output = self.text_normalizer.normalize(text_payload)

        # 5. Emit structural state execution fields to the Write-Ahead Log
        self.audit_logger.append_record({
            "partition_id": partition_id, "timestamp": time.time(), "blockchain_hash_head": blockchain_head_hash,
            "stream_sequence_index": committed_block.sequence_no, "operational_regime": stability_metrics["operational_regime"],
            "boundary_pass": boundary_pass, "boundary_faults": boundary_faults, "linguistic_anomalies": linguistic_anomalies
        })

        return {
            "transaction_status": "COMMITTED" if boundary_pass else "WARNING_FLAGGED",
            "scrubbed_text": scrubbed_text_output,
            "compliance_anomalies": linguistic_anomalies,
            "stability_profile": stability_metrics,
            "ledger_sequence": committed_block.sequence_no,
            "block_hash": blockchain_head_hash
        }

# ============================================================
