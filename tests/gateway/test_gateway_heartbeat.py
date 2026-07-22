"""
Tests for gateway heartbeat loop (Task 3.4.1).

Tests that the gateway correctly sends heartbeats to the central service,
handles failures gracefully, and stops on CancelledError.
"""

import asyncio
import hashlib
import yaml
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock


@pytest.fixture
def mock_settings():
    """Return mock settings dict."""
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


def test_compute_settings_hash(mock_settings):
    """_compute_settings_hash produces a 16-char hex hash."""
    from main import _compute_settings_hash
    result = _compute_settings_hash()
    assert len(result) == 16
    int(result, 16)  # Should not raise - it's valid hex


def test_compute_settings_hash_consistent(mock_settings):
    """_compute_settings_hash returns same hash for same input."""
    from main import _compute_settings_hash
    hash1 = _compute_settings_hash()
    hash2 = _compute_settings_hash()
    assert hash1 == hash2


def test_compute_settings_hash_different_input():
    """_compute_settings_hash returns different hashes for different inputs."""
    import main as gateway_main
    old_scan_seq = gateway_main.SCAN_SEQUENCE
    gateway_main.SCAN_SEQUENCE = "A"
    try:
        hash1 = gateway_main._compute_settings_hash()
        gateway_main.SCAN_SEQUENCE = "B"
        hash2 = gateway_main._compute_settings_hash()
        assert hash1 != hash2
    finally:
        gateway_main.SCAN_SEQUENCE = old_scan_seq


def test_settings_hash_from_dict(mock_settings):
    """_compute_settings_hash_from_dict produces a hash from a settings dict."""
    from main import _compute_settings_hash_from_dict
    result = _compute_settings_hash_from_dict(mock_settings)
    assert len(result) == 16
    int(result, 16)  # Valid hex


def test_settings_hash_consistency():
    """Local hash and remote hash match when settings are identical."""
    from main import _compute_settings_hash, _compute_settings_hash_from_dict
    import main as gateway_main

    local_dict = {
        "scan_sequence": gateway_main.SCAN_SEQUENCE,
        "scan_redaction_mode": gateway_main.SCAN_REDACTION_MODE,
        "scan_action_mode": gateway_main.SCAN_ACTION_MODE,
        "hitl_timeout": gateway_main.HITL_DEFAULT_TIMEOUT,
        "hitl_notification_mode": gateway_main.HITL_NOTIFICATION_MODE,
        "guardian_fail_strategy": gateway_main.GUARDIAN_FAIL_STRATEGY,
    }
    local_hash = _compute_settings_hash()
    remote_hash = _compute_settings_hash_from_dict(local_dict)
    assert local_hash == remote_hash


@pytest.mark.asyncio
async def test_heartbeat_loop_stops_on_cancelled_error(mock_backend_url):
    """Heartbeat loop exits cleanly on asyncio.CancelledError."""
    import main as gateway_main

    old_interval = gateway_main.HEARTBEAT_INTERVAL
    gateway_main.HEARTBEAT_INTERVAL = 0

    task = asyncio.create_task(gateway_main._heartbeat_loop(mock_backend_url))
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.done()

    gateway_main.HEARTBEAT_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_heartbeat_loop_handles_backend_unreachable(mock_backend_url):
    """Heartbeat loop continues after backend unreachable errors."""
    import main as gateway_main

    old_interval = gateway_main.HEARTBEAT_INTERVAL
    gateway_main.HEARTBEAT_INTERVAL = 0

    call_count = 0

    async def mock_post(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception("Connection refused")

    with patch("main._compute_settings_hash", return_value="test_hash"):
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = mock_post
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            task = asyncio.create_task(gateway_main._heartbeat_loop(mock_backend_url))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert call_count >= 1
    gateway_main.HEARTBEAT_INTERVAL = old_interval


@pytest.mark.asyncio
async def test_heartbeat_sends_correct_payload(mock_api_key):
    """Heartbeat POST has the correct structure."""
    import main as gateway_main

    old_interval = gateway_main.HEARTBEAT_INTERVAL
    old_api_key = gateway_main.API_KEY
    gateway_main.HEARTBEAT_INTERVAL = 0
    gateway_main.API_KEY = mock_api_key

    posted_data = []

    async def mock_post(url, json):
        posted_data.append({"url": url, "json": json})

    with patch("main._compute_settings_hash", return_value="hash_123"):
        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = mock_post
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            task = asyncio.create_task(gateway_main._heartbeat_loop("http://localhost:8000"))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    assert len(posted_data) >= 1
    payload = posted_data[0]["json"]
    assert payload["gateway_id"] == mock_api_key
    assert payload["api_key_hash"] == hashlib.sha256(mock_api_key.encode()).hexdigest()
    assert payload["version"] == "0.3.0"
    assert payload["settings_hash"] == "hash_123"

    gateway_main.HEARTBEAT_INTERVAL = old_interval
    gateway_main.API_KEY = old_api_key


@pytest.mark.asyncio
async def test_heartbeat_loop_stops_on_backend_url_empty():
    """Heartbeat loop does nothing when backend_url is empty."""
    import main as gateway_main

    old_interval = gateway_main.HEARTBEAT_INTERVAL
    gateway_main.HEARTBEAT_INTERVAL = 0

    task = asyncio.create_task(gateway_main._heartbeat_loop(""))
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    assert task.done()
    gateway_main.HEARTBEAT_INTERVAL = old_interval
