"""
ElderShield Rate Limiter

Provides a lightweight in-process rate limiter for the Streamlit
application.

Purpose:
- Reduce accidental API abuse.
- Reduce repeated Gemini requests.
- Provide a simple safety boundary for the public demo.

IMPORTANT:
This is NOT a replacement for production infrastructure such as
a reverse proxy, WAF, Redis-backed limiter, or cloud gateway.

Because Streamlit apps may run with multiple workers/containers,
this limiter is intentionally treated as a best-effort local
protection layer.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Optional


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_MAX_REQUESTS = 10
DEFAULT_WINDOW_SECONDS = 60


# ============================================================
# RESULT
# ============================================================

@dataclass(frozen=True)
class RateLimitResult:
    """
    Result returned by the rate limiter.
    """

    allowed: bool
    remaining: int
    retry_after: int
    limit: int
    window_seconds: int


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    """
    Simple sliding-window rate limiter.

    Each key gets its own request history.

    Example key:
        session identifier
        hashed client identifier
        authenticated user identifier

    Do not store sensitive personal information as the key.
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
    ) -> None:

        if max_requests < 1:
            raise ValueError(
                "max_requests must be at least 1."
            )

        if window_seconds < 1:
            raise ValueError(
                "window_seconds must be at least 1."
            )

        self.max_requests = int(
            max_requests
        )

        self.window_seconds = int(
            window_seconds
        )

        self._requests: dict[
            str,
            deque[float],
        ] = defaultdict(
            deque
        )

        self._lock = Lock()

    # --------------------------------------------------------
    # Internal cleanup
    # --------------------------------------------------------

    def _cleanup(
        self,
        timestamps: deque[float],
        now: float,
    ) -> None:
        """
        Remove timestamps outside the active window.
        """

        cutoff = (
            now
            - self.window_seconds
        )

        while timestamps and (
            timestamps[0] <= cutoff
        ):

            timestamps.popleft()

    # --------------------------------------------------------
    # Check request
    # --------------------------------------------------------

    def check(
        self,
        key: str,
        consume: bool = True,
    ) -> RateLimitResult:
        """
        Check whether a request is allowed.

        Args:
            key:
                Non-sensitive identifier for the requester.

            consume:
                If True, an allowed request consumes one slot.
                If False, this only checks current availability.
        """

        normalized_key = str(
            key or ""
        ).strip()

        if not normalized_key:

            raise ValueError(
                "Rate-limit key cannot be empty."
            )

        now = time.monotonic()

        with self._lock:

            timestamps = self._requests[
                normalized_key
            ]

            self._cleanup(
                timestamps,
                now,
            )

            current_count = len(
                timestamps
            )

            if current_count >= self.max_requests:

                retry_after = 1

                if timestamps:

                    retry_after = max(
                        1,
                        int(
                            self.window_seconds
                            - (
                                now
                                - timestamps[0]
                            )
                        ),
                    )

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=retry_after,
                    limit=self.max_requests,
                    window_seconds=self.window_seconds,
                )

            if consume:

                timestamps.append(
                    now
                )

                current_count += 1

            remaining = max(
                0,
                self.max_requests
                - current_count,
            )

            return RateLimitResult(
                allowed=True,
                remaining=remaining,
                retry_after=0,
                limit=self.max_requests,
                window_seconds=self.window_seconds,
            )

    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    def reset(
        self,
        key: Optional[str] = None,
    ) -> None:
        """
        Reset one key or the entire limiter.

        Useful for tests and controlled application resets.
        """

        with self._lock:

            if key is None:

                self._requests.clear()

                return

            normalized_key = str(
                key
            ).strip()

            self._requests.pop(
                normalized_key,
                None,
            )

    # --------------------------------------------------------
    # Remove inactive keys
    # --------------------------------------------------------

    def cleanup_all(self) -> None:
        """
        Remove inactive keys to prevent unbounded memory growth.
        """

        now = time.monotonic()

        with self._lock:

            empty_keys = []

            for key, timestamps in self._requests.items():

                self._cleanup(
                    timestamps,
                    now,
                )

                if not timestamps:

                    empty_keys.append(
                        key
                    )

            for key in empty_keys:

                self._requests.pop(
                    key,
                    None,
                )


# ============================================================
# GLOBAL APP LIMITERS
# ============================================================

# Separate limits allow different operations to have different
# budgets.

SCREEN_LIMITER = RateLimiter(
    max_requests=10,
    window_seconds=60,
)

AUDIO_LIMITER = RateLimiter(
    max_requests=5,
    window_seconds=60,
)

URL_LIMITER = RateLimiter(
    max_requests=20,
    window_seconds=60,
)

QR_LIMITER = RateLimiter(
    max_requests=20,
    window_seconds=60,
)


# ============================================================
# HELPER
# ============================================================

def check_limit(
    limiter: RateLimiter,
    key: str,
) -> RateLimitResult:
    """
    Convenience wrapper for application code.
    """

    return limiter.check(
        key,
        consume=True,
    )
