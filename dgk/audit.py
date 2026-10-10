from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from .serialization import to_canonical_json, drop_private_fields


# WRITE-AHEAD LOGGING AUDIT CHANNEL
# ============================================================
_GENESIS = "GENESIS"
_KEY_BYTES = 32


def _no_follow() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def load_or_create_key(key_path: str) -> bytes:
    """Return the audit signing key, creating a random one owner-only on first use.

    The key lives in its own file, never in the audit trail. Refuses a key
    file that other users can read or write.
    """
    try:
        fd = os.open(
            key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _no_follow(), 0o600
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(_KEY_BYTES))
    fd = os.open(key_path, os.O_RDONLY | _no_follow())
    with os.fdopen(fd, "rb") as handle:
        if os.fstat(handle.fileno()).st_mode & 0o077:
            raise PermissionError(f"audit key file must be owner-only: {key_path}")
        key = handle.read()
    if len(key) != _KEY_BYTES:
        raise ValueError(f"audit key file is malformed: {key_path}")
    return key


def open_private_append(path: str):
    """Open a file for appending, owner-only, refusing a symlink at the path."""
    if os.path.dirname(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | _no_follow()
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "a+", encoding="utf-8", buffering=1)


class AuditLog:
    """Append-only transaction logger. Each line is signed and chained."""

    def __init__(self, storage_path: str, key_path: Optional[str] = None):
        self.storage_path = storage_path
        # Owner-only, and refuses a symlink planted at the path.
        self.file_descriptor = open_private_append(storage_path)
        self._key = load_or_create_key(key_path or storage_path + ".key")
        self._last_signature = _GENESIS
        # A crash can leave half a line at the end. That is not tampering and
        # not a record, so it is cut off and the cut is itself recorded.
        self.recovered_bytes = self._repair_torn_tail()
        # Refuse to continue on top of a trail that has already been altered.
        for record in self.replay_log_history():
            self._last_signature = record["signature"]
        if self.recovered_bytes:
            self.append_record(
                {
                    "event": "recovered_torn_tail",
                    "dropped_bytes": self.recovered_bytes,
                    "timestamp": time.time(),
                }
            )

    def _repair_torn_tail(self) -> int:
        """Drop an unfinished last line. Returns the number of bytes removed.

        A last line with no newline is only kept if it is a whole record that
        passes the chain and signature check. Damage anywhere else is left for
        replay to refuse.
        """
        self.file_descriptor.flush()
        with open(self.storage_path, "rb") as reader:
            data = reader.read()
        if not data or data.endswith(b"\n"):
            return 0
        cut = data.rfind(b"\n") + 1
        tail = data[cut:]
        try:
            kept = self._parse_lines(data[:cut].decode("utf-8"))
            candidate = json.loads(tail.decode("utf-8"))
            self._check_chain(kept + [candidate])
        except (ValueError, UnicodeDecodeError):
            os.truncate(self.storage_path, cut)
            return len(tail)
        self.file_descriptor.write("\n")
        return 0

    @staticmethod
    def _parse_lines(text: str) -> List[Dict[str, Any]]:
        records = []
        for number, line in enumerate((l for l in text.splitlines() if l.strip()), 1):
            try:
                records.append(json.loads(line))
            except ValueError:
                raise ValueError(
                    f"audit record {number} is not valid JSON; the trail was "
                    "edited or damaged before its last line"
                ) from None
        return records

    def _check_chain(self, records: List[Dict[str, Any]]) -> str:
        """Verify every signature and link. Returns the last signature."""
        previous = _GENESIS
        for index, record in enumerate(records, start=1):
            body = {k: v for k, v in record.items() if k != "signature"}
            if body.get("prev_signature") != previous:
                raise ValueError(f"audit chain broken at record {index}")
            expected = sign_record(body, self._key)
            if not hmac.compare_digest(str(record.get("signature", "")), expected):
                raise ValueError(f"audit signature invalid at record {index}")
            previous = record["signature"]
        return previous

    def append_record(self, record: Dict[str, Any]) -> None:
        entry = {**record, "prev_signature": self._last_signature}
        entry["signature"] = sign_record(entry, self._key)
        self.file_descriptor.write(to_canonical_json(entry) + "\n")
        self._last_signature = entry["signature"]

    def close_stream(self) -> None:
        self.file_descriptor.close()

    def replay_log_history(self) -> List[Dict[str, Any]]:
        """Return every record after checking the signatures and the chain.

        Raises ValueError at the first record that was edited, removed,
        reordered, or signed with another key.
        """
        self.file_descriptor.flush()
        with open(self.storage_path, "r", encoding="utf-8") as file_reader:
            records = self._parse_lines(file_reader.read())
        self._check_chain(records)
        return records


# ============================================================
# CRYPTOGRAPHIC SECURITY ATTESTATION
# ============================================================
def sign_record(state: Dict[str, Any], secret_key: bytes) -> str:
    """Signs public dictionary state configurations via HMAC-SHA256."""
    payload = to_canonical_json(drop_private_fields(state)).encode()
    return hmac.new(secret_key, payload, hashlib.sha256).hexdigest()


def verify_record(state: Dict[str, Any], secret_key: bytes) -> bool:
    """Verifies state authenticity using timing-attack safe comparison."""
    target_signature = state.get("_sig")
    if not target_signature:
        return False
    return hmac.compare_digest(target_signature, sign_record(state, secret_key))


# ============================================================
