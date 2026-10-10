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

    def revoke(self, caller_id: str) -> bool:
        """Remove a caller at once. True if there was one to remove."""
        return self._grants.pop(caller_id, None) is not None

    def rotate(self, caller_id: str, new_token: str) -> None:
        """Replace a caller's token and keep its partitions. The old token stops
        working immediately. Raises KeyError for an unknown caller."""
        if not new_token:
            raise ValueError("new_token is required")
        grant = self._grants[caller_id]
        self._grants[caller_id] = _Grant(_digest(new_token), grant.partitions)

    def authorizes(self, caller_id: str, token: str, partition_id: str) -> bool:
        """True only if the caller is known, the token matches, and the
        partition is allowed. Anything that is not a string is refused."""
        if not all(isinstance(v, str) for v in (caller_id, token, partition_id)):
            return False
        grant = self._grants.get(caller_id)
        if grant is None:
            return False
        token_ok = hmac.compare_digest(grant.token_digest, _digest(token))
        return token_ok and partition_id in grant.partitions
