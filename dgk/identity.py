"""Caller identity: which callers may submit transactions, and to which partitions.

Each caller has a secret token. The registry stores only a SHA-256 digest of
the token, never the token itself. Tokens should be long random strings
(for example from secrets.token_urlsafe), so an unsalted digest is enough.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class _Grant:
    token_digest: str
    partitions: FrozenSet[str]


class CallerRegistry:
    """Maps caller identifiers to a token digest and an allowed partition set."""

    def __init__(self) -> None:
        self._grants: Dict[str, _Grant] = {}

    def register(self, caller_id: str, token: str, partitions: Iterable[str]) -> None:
        if not caller_id or not token:
            raise ValueError("caller_id and token are both required")
        self._grants[caller_id] = _Grant(_digest(token), frozenset(partitions))

    def authorizes(self, caller_id: str, token: str, partition_id: str) -> bool:
        """True only if the caller is known, the token matches, and the
        partition is allowed."""
        grant = self._grants.get(caller_id)
        if grant is None:
            return False
        token_ok = hmac.compare_digest(grant.token_digest, _digest(token))
        return token_ok and partition_id in grant.partitions
