"""Tests for HTTP client utilities."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from guardian.http_client import create_client, retry_with_backoff


@pytest.mark.asyncio
async def test_create_client_defaults():
    """Test create_client with default settings."""
    async with create_client() as client:
        assert isinstance(client, httpx.AsyncClient)
        assert client.timeout.connect == 5.0
        assert client.timeout.read == 10.0


@pytest.mark.asyncio
async def test_retry_with_backoff_success():
    """Test retry_with_backoff succeeds on first attempt."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        return "success"

    result = await retry_with_backoff(func, max_retries=3)
    assert result == "success"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_with_backoff_retries_on_500():
    """Test retry_with_backoff retries on 500 errors."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            response = MagicMock()
            response.status_code = 500
            raise httpx.HTTPStatusError("Server error", request=MagicMock(), response=response)
        return "success"

    result = await retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result == "success"
    assert call_count == 3


@pytest.mark.asyncio
async def test_retry_with_backoff_retries_on_429_with_retry_after():
    """Test retry_with_backoff respects Retry-After header."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            response = MagicMock()
            response.status_code = 429
            response.headers = {"retry-after": "0.01"}
            raise httpx.HTTPStatusError("Rate limited", request=MagicMock(), response=response)
        return "success"

    result = await retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result == "success"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_with_backoff_retries_on_network_error():
    """Test retry_with_backoff retries on network errors."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise httpx.RequestError("Network error", request=MagicMock())
        return "success"

    result = await retry_with_backoff(func, max_retries=3, base_delay=0.01)
    assert result == "success"
    assert call_count == 2


@pytest.mark.asyncio
async def test_retry_with_backoff_fails_after_max_retries():
    """Test retry_with_backoff fails after max retries."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        response = MagicMock()
        response.status_code = 500
        raise httpx.HTTPStatusError("Server error", request=MagicMock(), response=response)

    with pytest.raises(httpx.HTTPStatusError):
        await retry_with_backoff(func, max_retries=3, base_delay=0.01)

    assert call_count == 3


@pytest.mark.asyncio
async def test_retry_with_backoff_no_retry_on_400():
    """Test retry_with_backoff doesn't retry on client errors."""
    call_count = 0

    async def func():
        nonlocal call_count
        call_count += 1
        response = MagicMock()
        response.status_code = 400
        raise httpx.HTTPStatusError("Bad request", request=MagicMock(), response=response)

    with pytest.raises(httpx.HTTPStatusError):
        await retry_with_backoff(func, max_retries=3, base_delay=0.01)

    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_with_backoff_exponential_backoff():
    """Test retry_with_backoff uses exponential backoff."""
    call_times = []

    async def func():
        call_times.append(asyncio.get_event_loop().time())
        if len(call_times) < 3:
            response = MagicMock()
            response.status_code = 500
            raise httpx.HTTPStatusError("Server error", request=MagicMock(), response=response)
        return "success"

    with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await retry_with_backoff(func, max_retries=3, base_delay=0.1, jitter=False)

        # Should have slept twice (before 2nd and 3rd attempts)
        assert mock_sleep.call_count == 2
        # First sleep should be base_delay, second should be 2x base_delay
        sleep_times = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_times[0] == pytest.approx(0.1, abs=0.05)
        assert sleep_times[1] == pytest.approx(0.2, abs=0.05)
