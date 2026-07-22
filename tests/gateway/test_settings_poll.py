"""
Tests for gateway settings poll loop (Task 3.4.2).

Tests that the gateway correctly polls the backend for settings changes,
detects diffs, applies updates, and stops on CancelledError.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_settings_response():
    """Return a mock settings response from the backend."""
    return {
        "scan_sequence": "B",
        "scan_redaction_mode": "token",
        "scan_action_mode": "block",
        "hitl_timeout": 300,
        "hitl_notification_mode": "silent",
        "guardian_fail_strategy": "block",
    }


@pytest.fixture
def mock_api_key():
    """Return a mock API key."""
    return "test-api-key-12345"


@pytest.fixture
def mock_backend_url():
    """Return a mock backend URL."""
    return "http://localhost:8000"


def test_no_diff_no_update():
    """When local and remote settings match, no update is applied."""
    import main as gateway_main

    # Local state should match remote defaults
    local_dict = {
        "scan_sequence": gateway_main.SCAN_SEQUENCE,
        "scan_redaction_mode": gateway_main.SCAN_REDACTION_MODE,
        "scan_action_mode": gateway_main.SCAN_ACTION_MODE,
        "hitl_timeout": gateway_main.HITL_DEFAULT_TIMEOUT,
        "hitl_notification_mode": gateway_main.HITL_NOTIFICATION_MODE,
        "guardian_fail_strategy": gateway_main.GUARDIAN_FAIL_STRATEGY,
    }
    local_hash = gateway_main._compute_settings_hash()
    remote_hash = gateway_main._compute_settings_hash_from_dict(local_dict)
    assert local_hash == remote_hash


def test_settings_diff_detected(mock_settings_response):
    """When remote settings differ from local, hashes differ."""
    import main as gateway_main

    # Modify remote settings to differ
    remote_different = dict(mock_settings_response)
    remote_different["scan_sequence"] = "A"
    remote_different["hitl_timeout"] = 600

    local_hash = gateway_main._compute_settings_hash()
    remote_hash = gateway_main._compute_settings_hash_from_dict(remote_different)
    assert local_hash != remote_hash


@pytest.mark.asyncio
async def test_settings_poll_loop_stops_on_cancelled_error(mock_backend_url):
    """Settings poll loop exits cleanly on asyncio.CancelledError."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.done()

    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_handles_backend_unreachable(mock_backend_url):
    """Settings poll continues after backend unreachable errors."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    call_count = 0

    async def mock_get(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise Exception("Connection refused")

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert call_count >= 1
    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_applies_new_scan_sequence(mock_backend_url, mock_api_key):
    """Settings poll detects diff and applies scan_sequence change."""
    import main as gateway_main
    from gateway.core.scanner import PIIScanner

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    # Track HTTP calls
    get_calls = []

    async def mock_get(url, params=None):
        get_calls.append({"url": url, "params": params})
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "scan_sequence": "A",  # Different from local "B"
            "scan_redaction_mode": "token",
            "scan_action_mode": "block",
            "hitl_timeout": 300,
            "hitl_notification_mode": "silent",
            "guardian_fail_strategy": "block",
        }
        return mock_response

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        # Reset scanner scan_sequence to match local state
        gateway_main.scanner.scan_sequence = gateway_main.SCAN_SEQUENCE

        task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Verify scanner settings were updated
    assert gateway_main.SCAN_SEQUENCE == "A"
    assert gateway_main.proxy_engine.scan_sequence == "A"
    assert gateway_main.scanner.scan_sequence == "A"

    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_applies_new_hitl_timeout(mock_backend_url, mock_api_key):
    """Settings poll detects diff and applies hitl_timeout change."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    old_hitl_timeout = gateway_main.HITL_DEFAULT_TIMEOUT

    async def mock_get(*args, **kwargs):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "scan_sequence": gateway_main.SCAN_SEQUENCE,
            "scan_redaction_mode": gateway_main.SCAN_REDACTION_MODE,
            "scan_action_mode": gateway_main.SCAN_ACTION_MODE,
            "hitl_timeout": 600,  # Different from local
            "hitl_notification_mode": gateway_main.HITL_NOTIFICATION_MODE,
            "guardian_fail_strategy": gateway_main.GUARDIAN_FAIL_STRATEGY,
        }
        return mock_response

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert gateway_main.HITL_DEFAULT_TIMEOUT == 600
    assert gateway_main.hitl.default_timeout == 600

    # Restore
    gateway_main.HITL_DEFAULT_TIMEOUT = old_hitl_timeout
    gateway_main.hitl.default_timeout = old_hitl_timeout
    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_applies_new_guardian_strategy(mock_backend_url, mock_api_key):
    """Settings poll detects diff and applies guardian_fail_strategy change."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    old_strategy = gateway_main.GUARDIAN_FAIL_STRATEGY

    async def mock_get(*args, **kwargs):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "scan_sequence": gateway_main.SCAN_SEQUENCE,
            "scan_redaction_mode": gateway_main.SCAN_REDACTION_MODE,
            "scan_action_mode": gateway_main.SCAN_ACTION_MODE,
            "hitl_timeout": gateway_main.HITL_DEFAULT_TIMEOUT,
            "hitl_notification_mode": gateway_main.HITL_NOTIFICATION_MODE,
            "guardian_fail_strategy": "warn",  # Different from local
        }
        return mock_response

    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert gateway_main.GUARDIAN_FAIL_STRATEGY == "warn"
    assert gateway_main.guardian.fail_strategy == "warn"

    # Restore
    gateway_main.GUARDIAN_FAIL_STRATEGY = old_strategy
    gateway_main.guardian.fail_strategy = old_strategy
    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_no_response_200(mock_backend_url):
    """Settings poll skips when backend returns non-200."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    gateway_main.SETTINGS_POLL_INTERVAL = 0

    async def mock_get(*args, **kwargs):
        mock_response = MagicMock()
        mock_response.status_code = 500
        return mock_response

    original_sequence = gateway_main.SCAN_SEQUENCE
    with patch("httpx.AsyncClient") as MockClient:
        mock_client = AsyncMock()
        mock_client.get = mock_get
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        task = asyncio.create_task(gateway_main._settings_poll_loop(mock_backend_url))
        await asyncio.sleep(0.1)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Settings should not have changed
    assert gateway_main.SCAN_SEQUENCE == original_sequence
    gateway_main.SETTINGS_POLL_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_settings_poll_empty_url(mock_backend_url):
    """Settings poll does nothing when backend_url is empty."""
    import main as gateway_main

    old_interval = gateway_main.SETTINGS_POLL_INTERVAL
    old_url = gateway_main.HITL_CLOUD_URL

    gateway_main.SETTINGS_POLL_INTERVAL = 0
    gateway_main.HITL_CLOUD_URL = ""

    task = asyncio.create_task(gateway_main._settings_poll_loop(gateway_main.HITL_CLOUD_URL))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert task.done()

    # Restore
    gateway_main.HITL_CLOUD_URL = old_url
    gateway_main.SETTINGS_POLL_INTERVAL = old_interval
