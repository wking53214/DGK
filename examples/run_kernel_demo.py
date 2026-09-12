"""
The recovered entrypoint's scenario, run against the rebuilt kernel.

Shows a healthy transaction committing, a forbidden one being rejected before
anything reaches the ledger, and the write-ahead log replayed afterwards.
"""

import json
import os
import tempfile

from dgk import SYSTEM_NAME, SYSTEM_VERSION, GovernanceOrchestrationKernel

TELEMETRY = {
    "latency": 134.2,
    "abort_rate": 0.008,
    "reentry_rate": 0.04,
    "load_depth": 280.0,
    "determinism_index": 0.998,
}
JARGON = "We are utilizing holistic paradigms to operationalize granular and suboptimal systems."
PARTITION = "region-us-east-production"


def main() -> None:
    print(f"Loading {SYSTEM_NAME} (v{SYSTEM_VERSION})...")
    log_path = os.path.join(tempfile.mkdtemp(prefix="dgk-demo-"), "audit.log")
    kernel = GovernanceOrchestrationKernel(log_path=log_path)

    print("\n--- Phase 1: structural state ingestion ---")
    committed = kernel.process_transaction(PARTITION, TELEMETRY, JARGON)
    print(json.dumps(committed, indent=4))

    print("\n--- Phase 2: perimeter rejection ---")
    rejected = kernel.process_transaction(PARTITION, TELEMETRY, "this text is forbidden")
    print(json.dumps(rejected, indent=4))
    print("  Nothing was committed: the ledger head is unchanged and the")
    print("  write-ahead log has no record of the rejected request.")

    print("\n--- Phase 3: materialized state from the ledger ---")
    state = kernel.materialization_runtime.materialize_state(PARTITION)
    print("  ", dict(state))

    print("\n--- Phase 4: write-ahead log replay ---")
    for index, record in enumerate(kernel.audit_logger.replay_log_history()):
        print(f"  [{index}] {json.dumps(record)[:150]}")

    kernel.audit_logger.close_stream()
    print(f"\nAudit log written to {log_path}")


if __name__ == "__main__":
    main()
