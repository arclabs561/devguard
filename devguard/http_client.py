"""Shared HTTP client utilities with best practices for monitoring."""

import asyncio
import logging
import random
from collections.abc import Callable
from typing import Any

import httpx
from httpx import Timeout

logger = logging.getLogger(__name__)

# Default timeout configuration for monitoring
DEFAULT_TIMEOUT = Timeout(
    connect=5.0,  # Connection establishment
    read=10.0,  # Reading response
    write=5.0,  # Sending request
    pool=2.0,  # Pool acquisition
)

# Default connection limits
DEFAULT_LIMITS = httpx.Limits(
    max_connections=20,
    max_keepalive_connections=10,
    keepalive_expiry=15.0,
)


def create_client(
    timeout: Timeout | None = None,
    limits: httpx.Limits | None = None,
) -> httpx.AsyncClient:
    """Create an AsyncClient with sensible defaults for monitoring."""
    return httpx.AsyncClient(
        timeout=timeout or DEFAULT_TIMEOUT,
        limits=limits or DEFAULT_LIMITS,
    )


async def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 32.0,
    jitter: bool = True,
) -> Any:
    """
    Retry a coroutine with exponential backoff.

    For rate limiting (429), respects Retry-After header if available.
    For other transient errors, uses exponential backoff with optional jitter.
    """
    last_exception = None

    for attempt in range(max_retries):
        try:
            return await func()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                # Respect Retry-After header if present
                retry_after = e.response.headers.get("retry-after")
                if retry_after:
                    try:
                        delay = float(retry_after)
                    except ValueError:
                        delay = base_delay * (2**attempt)
                else:
                    delay = base_delay * (2**attempt)

                logger.info(f"Rate limited. Retrying after {delay}s")
                await asyncio.sleep(delay)
            elif 500 <= e.response.status_code < 600:
                # Server error - retry with backoff
                delay = min(base_delay * (2**attempt), max_delay)
                if jitter:
                    delay *= 0.5 + random.random()

                logger.info(
                    f"Server error {e.response.status_code}. "
                    f"Retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(delay)
            else:
                # Client error or other - don't retry
                raise
            last_exception = e
        except (httpx.ConnectError, httpx.TimeoutException) as e:
            # Network/timeout error - retry with backoff
            delay = min(base_delay * (2**attempt), max_delay)
            if jitter:
                delay *= 0.5 + random.random()

            logger.info(
                f"Network/timeout error. "
                f"Retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})"
            )
            await asyncio.sleep(delay)
            last_exception = e
        except httpx.RequestError as e:
            # Other request errors - retry with backoff
            delay = min(base_delay * (2**attempt), max_delay)
            if jitter:
                delay *= 0.5 + random.random()

            logger.info(
                f"Request error. Retrying in {delay:.2f}s (attempt {attempt + 1}/{max_retries})"
            )
            await asyncio.sleep(delay)
            last_exception = e

    if last_exception:
        raise last_exception
