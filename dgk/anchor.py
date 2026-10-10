"""External anchors for ledger heads.

The ledger and the audit trail can each be cut back to an earlier, internally
valid state by someone who can write both files. Nothing inside those files can
reveal that, because a shorter chain is still a valid chain. A head anchor is a
record of the newest head hash kept somewhere that person cannot reach.

DGK does not choose that place. The kernel calls `publish` after every commit
and, on startup, refuses to run if the ledger no longer contains a head the
anchor has seen. What the anchor is (a different host, write-once storage, a
second organization's log) is the operator's decision, and an anchor on the
same disk as the ledger adds almost nothing.
"""

from __future__ import annotations

import json
import os
from typing import Dict, Mapping, Protocol, Tuple

from .audit import open_private_append

Heads = Mapping[str, Tuple[int, str]]


class AnchorMismatch(ValueError):
    """The ledger no longer holds a head that the anchor has already seen."""


class HeadAnchor(Protocol):
    """Where the newest head hash of each partition is kept outside the kernel."""

    def publish(self, partition_id: str, sequence_no: int, head_hash: str) -> None:
        """Record that `partition_id` reached `sequence_no` with this head."""
        ...

    def latest(self) -> Heads:
        """Newest (sequence_no, head_hash) the anchor holds for each partition."""
        ...


class FileHeadAnchor:
    """Reference anchor: one JSON line per commit in an append-only file.

    Only as strong as where the file lives. Put it on storage the kernel's
    operators cannot rewrite, or replace it with something that is.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._file = open_private_append(path)

    def publish(self, partition_id: str, sequence_no: int, head_hash: str) -> None:
        line = json.dumps(
            {"partition_id": partition_id, "sequence_no": sequence_no, "head": head_hash},
            sort_keys=True,
        )
        self._file.write(line + "\n")
        self._file.flush()
        os.fsync(self._file.fileno())

    def latest(self) -> Heads:
        self._file.flush()
        newest: Dict[str, Tuple[int, str]] = {}
        with open(self.path, "r", encoding="utf-8") as reader:
            for line in reader:
                if not line.strip():
                    continue
                row = json.loads(line)
                seen = newest.get(row["partition_id"])
                if seen is None or row["sequence_no"] >= seen[0]:
                    newest[row["partition_id"]] = (row["sequence_no"], row["head"])
        return newest

    def close(self) -> None:
        self._file.close()
