from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict, List

from .serialization import canonicalize_dictionary, filter_private_keys


# WRITE-AHEAD LOGGING AUDIT CHANNEL
# ============================================================
class AuditTrailWAL:
    """Append-only transaction logger handling structural engine storage operations."""

    def __init__(self, storage_path: str):
        self.storage_path = storage_path
        if os.path.dirname(storage_path):
            os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        # Owner-only permissions, and refuse to follow a symlink planted at
        # the path, so another local user cannot read the trail or redirect
        # the writes into a file of their choosing.
        flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(storage_path, flags, 0o600)
        self.file_descriptor = os.fdopen(fd, "a+", encoding="utf-8", buffering=1)

    def append_record(self, record: Dict[str, Any]) -> None:
        self.file_descriptor.write(canonicalize_dictionary(record) + "\n")

    def close_stream(self) -> None:
        self.file_descriptor.close()

    def replay_log_history(self) -> List[Dict[str, Any]]:
        self.file_descriptor.flush()
        with open(self.storage_path, "r", encoding="utf-8") as file_reader:
            return [json.loads(line) for line in file_reader if line.strip()]


# ============================================================
# CRYPTOGRAPHIC SECURITY ATTESTATION
# ============================================================
def generate_hmac_signature(state: Dict[str, Any], secret_key: bytes) -> str:
    """Signs public dictionary state configurations via HMAC-SHA256."""
    payload = canonicalize_dictionary(filter_private_keys(state)).encode()
    return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()


def verify_hmac_signature(state: Dict[str, Any], secret_key: bytes) -> bool:
    """Verifies state authenticity using timing-attack safe comparison."""
    target_signature = state.get("_sig")
    if not target_signature:
        return False
    return hmac.compare_digest(
        target_signature, generate_hmac_signature(state, secret_key)
    )


# ============================================================
