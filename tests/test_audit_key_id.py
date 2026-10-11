"""Audit entries record the algorithm and key ID that signed them."""

import json

import pytest

from dgk.audit import SIGNATURE_ALGORITHM, AuditLog, key_id_for


def _lines(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_new_entries_carry_algorithm_and_key_id(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path))
    log.append_record({"event": "commit"})
    log.close_stream()
    entry = _lines(log_path)[0]
    assert entry["signature_algorithm"] == SIGNATURE_ALGORITHM == "hmac-sha256"
    assert entry["key_id"].startswith("key-")
    key = (tmp_path / "audit.log.key").read_bytes()
    assert key.hex() not in entry["key_id"]


def test_key_id_is_derived_and_stable(tmp_path):
    key = b"0123456789abcdef0123456789abcdef"
    assert key_id_for(key) == key_id_for(key)
    assert key_id_for(key) != key_id_for(key + b"x")


def test_log_with_key_ids_reopens_and_verifies(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path))
    log.append_record({"event": "one"})
    log.close_stream()
    reopened = AuditLog(str(log_path))
    reopened.append_record({"event": "two"})
    reopened.close_stream()
    assert len(_lines(log_path)) == 2


def test_entry_from_another_key_is_named_in_the_refusal(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path), str(tmp_path / "key-a"))
    log.append_record({"event": "one"})
    log.close_stream()
    other = AuditLog.__new__(AuditLog)
    other.storage_path = str(log_path)
    other._key = b"f" * 32
    other._key_id = key_id_for(other._key)
    with pytest.raises(ValueError, match="signed with key"):
        other._check_chain(_lines(log_path))
