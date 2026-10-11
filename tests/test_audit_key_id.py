"""Audit entries record the algorithm and key ID that signed them."""

import json

import pytest

from dgk.audit import SIGNATURE_ALGORITHM, AuditLog


def _lines(path):
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_new_entries_carry_algorithm_and_key_id(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path), key_id="test-key")
    log.append_record({"event": "commit"})
    log.close_stream()
    entry = _lines(log_path)[0]
    assert entry["algorithm"] == SIGNATURE_ALGORITHM == "hmac-sha256"
    assert entry["key_id"] == "test-key"
    key = (tmp_path / "audit.log.key").read_bytes()
    assert key.hex() not in entry["key_id"]


def test_key_id_must_be_named(tmp_path):
    with pytest.raises(ValueError, match="caller-named key_id"):
        AuditLog(str(tmp_path / "audit.log"))


def test_log_with_key_ids_reopens_and_verifies(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path), key_id="test-key")
    log.append_record({"event": "one"})
    log.close_stream()
    reopened = AuditLog(str(log_path), key_id="test-key")
    reopened.append_record({"event": "two"})
    reopened.close_stream()
    assert len(_lines(log_path)) == 2


def test_entry_from_another_key_is_named_in_the_refusal(tmp_path):
    log_path = tmp_path / "audit.log"
    log = AuditLog(str(log_path), str(tmp_path / "key-a"), key_id="test-key")
    log.append_record({"event": "one"})
    log.close_stream()
    other = AuditLog.__new__(AuditLog)
    other.storage_path = str(log_path)
    other._key = b"f" * 32
    other._key_id = "other-key"
    with pytest.raises(ValueError, match="signed with key"):
        other._check_chain(_lines(log_path))
