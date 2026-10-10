"""A cap on how many refusals from unauthenticated callers reach the audit trail.

A caller who fails the identity check has proved nothing, so the kernel will
not let such callers write unbounded records into a signed, append-only file.
Within each window the first `limit` refusals are recorded in full. The rest
are counted, and the count is written as one signed summary record when the
window ends, so the flood is visible without filling the disk.
"""

from __future__ import annotations

import time
from typing import Callable


class RefusalBudget:
    """Counts refusals per window and says whether one may be written in full."""

    def __init__(
        self,
        limit: int = 60,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._window_start = clock()
        self._used = 0
        self._suppressed = 0
        self._rolled = 0

    def admit(self) -> bool:
        """True if this refusal may be written in full; False if only counted."""
        now = self._clock()
        if now - self._window_start >= self.window_seconds:
            self._rolled += self._suppressed
            self._suppressed = 0
            self._used = 0
            self._window_start = now
        if self._used < self.limit:
            self._used += 1
            return True
        self._suppressed += 1
        return False

    def take_rolled(self) -> int:
        """Refusals counted but not written in windows that have ended. Resets."""
        count, self._rolled = self._rolled, 0
        return count

    def take_all(self) -> int:
        """Every counted-but-unwritten refusal, including the open window. Resets."""
        count = self._rolled + self._suppressed
        self._rolled = 0
        self._suppressed = 0
        return count
