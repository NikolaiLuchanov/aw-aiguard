"""Tests for gateway/core/audit.py — AuditLogger."""

import os
import json
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas import AuditEvent
from gateway.core.audit import AuditLogger


@pytest.mark.unit
class TestAuditLogger:
    @pytest.fixture
    def logger(self, tmp_path):
        buffer_path = str(tmp_path / "audit_buffer.jsonl")
        return AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=buffer_path,
            batch_size=2,
            flush_interval=0.1,
        )

    def test_init_backend_url_derived(self, tmp_path):
        """backend_url is derived from base_url (strip path component)."""
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
        )
        assert aud.backend_url == "http://localhost:8000"

    def test_init_expands_buffer_path(self, tmp_path):
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path="~/test/buf.jsonl",
        )
        assert aud.buffer_path.startswith(os.path.expanduser("~"))

    # --- log_event ---

    @pytest.mark.asyncio
    async def test_log_event_queues_and_hashes(self, logger):
        event = AuditEvent(api_key="k", event_type="allow", component="proxy")
        await logger.log_event(
            api_key="k",
            event_type="allow",
            component="proxy",
            prompt="hello",
        )
        assert logger.queue.qsize() == 1
        queued = await logger.queue.get()
        assert queued.api_key == "k"
        assert queued.prompt_hash is not None
        assert len(queued.prompt_hash) == 64

    @pytest.mark.asyncio
    async def test_log_event_with_provided_hash(self, logger):
        await logger.log_event(
            api_key="k",
            event_type="allow",
            component="proxy",
            prompt="",
            prompt_hash="precomputed",
        )
        queued = await logger.queue.get()
        assert queued.prompt_hash == "precomputed"

    # --- log (direct) ---

    @pytest.mark.asyncio
    async def test_log_puts_event_in_queue(self, logger):
        event = AuditEvent(api_key="k", event_type="allow", component="proxy")
        await logger.log(event)
        assert logger.queue.qsize() == 1

    @pytest.mark.asyncio
    async def test_log_drops_on_queue_full(self, tmp_path, caplog):
        aud = AuditLogger(
            base_url="http://localhost:8000",
            buffer_path=str(tmp_path / "buf.jsonl"),
            max_queue_size=2,
        )
        await aud.log(AuditEvent(api_key="k", event_type="allow", component="p"))
        await aud.log(AuditEvent(api_key="k", event_type="allow", component="p"))
        await aud.log(AuditEvent(api_key="k", event_type="allow", component="p"))
        # Third event should be dropped
        assert aud.queue.qsize() == 2

    # --- _write_to_buffer ---

    @pytest.mark.asyncio
    async def test_write_to_buffer_creates_jsonl(self, logger):
        events = [
            AuditEvent(api_key="k1", event_type="block", component="g"),
            AuditEvent(api_key="k2", event_type="allow", component="p"),
        ]
        await logger._write_to_buffer(events)
        assert os.path.exists(logger.buffer_path)
        with open(logger.buffer_path) as f:
            lines = f.readlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["api_key"] == "k1"

    @pytest.mark.asyncio
    async def test_write_to_buffer_creates_parent_dirs(self, tmp_path):
        deep_path = str(tmp_path / "a" / "b" / "c" / "buf.jsonl")
        aud = AuditLogger(
            base_url="http://localhost:8000",
            buffer_path=deep_path,
        )
        events = [AuditEvent(api_key="k", event_type="allow", component="p")]
        await aud._write_to_buffer(events)
        assert os.path.exists(deep_path)

    # --- _replay_buffer ---

    @pytest.mark.asyncio
    async def test_replay_buffer_sends_to_backend(self, logger, tmp_path):
        # Pre-fill the buffer
        event_data = {"api_key": "k", "event_type": "allow", "component": "p"}
        with open(logger.buffer_path, "w") as f:
            f.write(json.dumps(event_data) + "\n")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post = AsyncMock(return_value=mock_response)

        with patch.object(logger._client, "post", mock_post):
            await logger._replay_buffer()

        mock_post.assert_called_once()
        # Buffer file should be deleted on success
        assert not os.path.exists(logger.buffer_path)

    @pytest.mark.asyncio
    async def test_replay_buffer_keeps_on_failure(self, logger, tmp_path):
        event_data = {"api_key": "k", "event_type": "allow", "component": "p"}
        with open(logger.buffer_path, "w") as f:
            f.write(json.dumps(event_data) + "\n")

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch.object(logger._client, "post", new=AsyncMock(return_value=mock_response)):
            await logger._replay_buffer()

        # Buffer should remain
        assert os.path.exists(logger.buffer_path)

    @pytest.mark.asyncio
    async def test_replay_buffer_noop_when_missing(self, logger):
        """No error when buffer file doesn't exist."""
        await logger._replay_buffer()  # Should not raise

    # --- start / stop ---

    @pytest.mark.asyncio
    async def test_start_creates_worker(self, logger):
        await logger.start()
        assert logger._worker_task is not None
        await logger.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_worker(self, logger):
        await logger.start()
        await logger.stop()
        assert logger._worker_task.done()

    # --- _flush_remaining ---

    @pytest.mark.asyncio
    async def test_flush_remaining_on_shutdown(self, logger):
        await logger.log(AuditEvent(api_key="k", event_type="allow", component="p"))
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post = AsyncMock(return_value=mock_response)
        with patch.object(logger._client, "post", mock_post):
            await logger._flush_remaining()
        mock_post.assert_called_once()

    # --- backend_url kwarg (finding #4) ---

    def test_init_explicit_backend_url(self, tmp_path):
        """Explicit backend_url wins over derivation from base_url."""
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
            backend_url="http://central:9999",
        )
        assert aud.backend_url == "http://central:9999"

    def test_init_explicit_backend_url_strips_trailing_slash(self, tmp_path):
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
            backend_url="http://central:9999/",
        )
        assert aud.backend_url == "http://central:9999"

    def test_init_fallback_derivation_when_no_explicit_url(self, tmp_path):
        """Legacy behavior: dirname(base_url) when backend_url is not given."""
        aud = AuditLogger(
            base_url="http://localhost:8000/guardian",
            buffer_path=str(tmp_path / "buf.jsonl"),
        )
        assert aud.backend_url == "http://localhost:8000"
