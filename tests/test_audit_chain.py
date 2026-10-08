import json
import os
import stat
import tempfile

import pytest

from dgk.audit import AuditLog, load_or_create_key


def fresh_path():
    return os.path.join(tempfile.mkdtemp(), "trail.log")


def write_three(path):
    log = AuditLog(path)
    for n in range(3):
        log.append_record({"n": n})
    log.close_stream()


def test_reopened_trail_verifies_and_the_chain_continues():
    path = fresh_path()
    write_three(path)
    log = AuditLog(path)
    log.append_record({"n": 3})
    assert len(log.replay_log_history()) == 4
    log.close_stream()


def test_key_file_is_created_owner_only():
    path = fresh_path()
    AuditLog(path).close_stream()
    key_path = path + ".key"
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600


def test_key_is_not_written_into_the_trail():
    path = fresh_path()
    write_three(path)
    key = load_or_create_key(path + ".key")
    assert key.hex() not in open(path).read()


def test_deleting_a_middle_line_is_detected():
    path = fresh_path()
    write_three(path)
    lines = open(path).read().splitlines()
    del lines[1]
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        AuditLog(path)


def test_reordering_lines_is_detected():
    path = fresh_path()
    write_three(path)
    lines = open(path).read().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    open(path, "w").write("\n".join(lines) + "\n")
    with pytest.raises(ValueError):
        AuditLog(path)


def test_a_different_key_cannot_verify_the_trail():
    path = fresh_path()
    write_three(path)
    os.remove(path + ".key")
    with pytest.raises(ValueError):
        AuditLog(path)


def test_group_readable_key_file_is_refused():
    path = fresh_path()
    AuditLog(path).close_stream()
    os.chmod(path + ".key", 0o640)
    with pytest.raises(PermissionError):
        load_or_create_key(path + ".key")


def test_symlinked_key_file_is_refused():
    path = fresh_path()
    AuditLog(path).close_stream()
    target = os.path.join(os.path.dirname(path), "elsewhere.key")
    with open(target, "wb") as handle:
        handle.write(b"x" * 32)
    link = os.path.join(os.path.dirname(path), "linked.key")
    os.symlink(target, link)
    with pytest.raises(OSError):
        load_or_create_key(link)


def test_records_are_json_lines_with_a_signature():
    path = fresh_path()
    write_three(path)
    first = json.loads(open(path).readline())
    assert first["prev_signature"] == "GENESIS"
    assert len(first["signature"]) == 64
