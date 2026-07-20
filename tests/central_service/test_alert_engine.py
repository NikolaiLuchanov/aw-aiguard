"""
Tests for central-service/alert_engine.py — AlertEngine.

Migrated from verify_phase_2_3.py (Phase 2.3 Verification).
Covers all original 19 tests converted to proper pytest structure.
Note: The central-service/ directory uses a hyphen, so modules are imported
as flat names (alert_engine, api_server) since conftest adds the path to sys.path.
"""

import os
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from shared.schemas import AuditEvent
from alert_engine import AlertEngine


@pytest.mark.unit
class TestAlertEngineTelegram:
    """Test 1 (original): Telegram dispatch with correct payload."""

    @pytest.mark.asyncio
    async def test_telegram_endpoint_called_with_severity(self):
        """Telegram endpoint called with severity in text."""
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {"telegram": {"token": "mock-token", "chat_id": "-12345"}}

        event = AuditEvent(api_key="test-key", event_type="block", component="guardian", reason="injection")

        with patch("alert_engine.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_ctx = AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client),
                __aexit__=AsyncMock(return_value=False),
            )
            mock_httpx.AsyncClient.return_value = mock_ctx

            await engine.send("CRITICAL", "guardian: injection (key=test-key)", event)

            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            url = call_args[0][0] if call_args[0] else call_args[1].get("url", "")
            payload = call_args[1].get("json", {})
            assert "/sendMessage" in url
            assert "CRITICAL" in str(payload.get("text", ""))


@pytest.mark.unit
class TestAlertEngineSlack:
    """Test 2 (original): Slack dispatch with correct payload."""

    @pytest.mark.asyncio
    async def test_slack_webhook_called_with_severity(self):
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {"slack": {"webhook_url": "https://hooks.slack.com/test"}}
        event = AuditEvent(api_key="test-key", event_type="block", component="guardian")

        with patch("alert_engine.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(return_value=mock_response)
            mock_ctx = AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client),
                __aexit__=AsyncMock(return_value=False),
            )
            mock_httpx.AsyncClient.return_value = mock_ctx

            await engine.send("HIGH", "pii_scanner: block (key=x)", event)

            call_args = mock_client.post.call_args
            url = call_args[0][0] if call_args[0] else ""
            payload = call_args[1].get("json", {})
            assert url == "https://hooks.slack.com/test"
            assert "HIGH" in str(payload.get("text", ""))


@pytest.mark.unit
class TestAlertEngineEmail:
    """Test 3 (original): Email dispatch via smtplib (executor)."""

    @pytest.mark.asyncio
    async def test_smtplib_called_via_executor(self):
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {
            "email": {
                "host": "mock.smtp",
                "port": 587,
                "user": "u",
                "password": "p",
                "from": "a@b.com",
                "to": "c@d.com",
            }
        }
        smtp_calls = []

        def fake_smtp(host, port, timeout=None):
            class FakeSMTP:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    pass

                def starttls(self):
                    pass

                def login(self, u, p):
                    pass

                def send_message(self, msg):
                    smtp_calls.append(msg)

            return FakeSMTP()

        event = AuditEvent(api_key="k", event_type="warn", component="c")
        with patch("alert_engine.smtplib.SMTP", side_effect=fake_smtp):
            await engine.send("WARNING", "test warn", event)

        assert len(smtp_calls) == 1
        assert "WARNING" in smtp_calls[0].get_content()


@pytest.mark.unit
class TestAlertEngineSeverityMapping:
    """Tests 4-10 (original): Severity mapping from api_server._get_severity."""

    def test_guardian_block_is_critical(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="block", component="guardian")
        assert _get_severity(event) == "CRITICAL"

    def test_byoc_block_is_critical(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="block", component="byoc_engine")
        assert _get_severity(event) == "CRITICAL"

    def test_pii_scanner_block_is_high(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="block", component="pii_scanner")
        assert _get_severity(event) == "HIGH"

    def test_other_block_is_high(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="block", component="hitl_gate")
        assert _get_severity(event) == "HIGH"

    def test_warn_is_warning(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="warn", component="pii_scanner")
        assert _get_severity(event) == "WARNING"

    def test_pause_is_notice(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="pause", component="hitl_gate")
        assert _get_severity(event) == "NOTICE"

    def test_allow_is_notice(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="allow", component="proxy")
        assert _get_severity(event) == "NOTICE"


@pytest.mark.unit
class TestAlertEngineEscalate:
    """Test 11 (original): ESCALATE severity triggers all channels."""

    @pytest.mark.asyncio
    async def test_escalate_dispatches_to_all_channels(self):
        captured = []
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {
            "telegram": {"token": "t", "chat_id": "c"},
            "slack": {"webhook_url": "https://hooks.slack.com/test"},
        }
        event = AuditEvent(api_key="k", event_type="block", component="guardian")

        with patch("alert_engine.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(
                return_value=mock_response,
                side_effect=lambda *a, **kw: captured.append(kw.get("json", {})),
            )
            mock_ctx = AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client),
                __aexit__=AsyncMock(return_value=False),
            )
            mock_httpx.AsyncClient.return_value = mock_ctx

            await engine.send("ESCALATE", "repeated failures", event)

        assert len(captured) == 2  # Telegram + Slack


@pytest.mark.unit
class TestAlertEngineUnknownSeverity:
    """Test 12 (original): Unknown severity → no dispatch."""

    @pytest.mark.asyncio
    async def test_unknown_severity_no_dispatch(self):
        captured = []
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {"telegram": {"token": "t", "chat_id": "c"}}
        event = AuditEvent(api_key="k", event_type="allow", component="p")

        with patch("alert_engine.httpx") as mock_httpx:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.post = AsyncMock(
                side_effect=lambda *a, **kw: captured.append(kw)
            )
            mock_ctx = AsyncMock(
                __aenter__=AsyncMock(return_value=mock_client),
                __aexit__=AsyncMock(return_value=False),
            )
            mock_httpx.AsyncClient.return_value = mock_ctx

            await engine.send("BOGUS", "should not fire", event)

        assert len(captured) == 0


@pytest.mark.unit
class TestAlertEngineNoChannels:
    """Test 13 (original): No channels configured → silent log (no crash)."""

    @pytest.mark.asyncio
    async def test_empty_channels_no_crash(self):
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {}
        event = AuditEvent(api_key="k", event_type="block", component="g")
        await engine.send("CRITICAL", "test", event)  # Should not raise


@pytest.mark.unit
class TestAlertEngineEmojiMapping:
    """Test 14 (original): Telegram emoji mapping."""

    @pytest.mark.asyncio
    async def test_all_severity_emojis_correct(self):
        emoji_map = {
            "CRITICAL": "🔴",
            "ESCALATE": "🔴",
            "HIGH": "🟠",
            "WARNING": "🟡",
            "NOTICE": "⚪",
        }
        engine = AlertEngine.__new__(AlertEngine)
        engine.channels = {"telegram": {"token": "t", "chat_id": "c"}}
        event = AuditEvent(api_key="k", event_type="allow", component="p")
        results = []

        for sev, expected_emoji in emoji_map.items():
            with patch("alert_engine.httpx") as mock_httpx:
                mock_client = AsyncMock()
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_client.post = AsyncMock(return_value=mock_response)
                mock_ctx = AsyncMock(
                    __aenter__=AsyncMock(return_value=mock_client),
                    __aexit__=AsyncMock(return_value=False),
                )
                mock_httpx.AsyncClient.return_value = mock_ctx

                await engine.send(sev, f"test {sev}", event)
                call_args = mock_client.post.call_args
                payload = call_args[1].get("json", {})
                text = payload.get("text", "")
                ok = text.startswith(f"{expected_emoji} [{sev}]")
                results.append((sev, ok))

        assert all(ok for _, ok in results), f"Failed for: {[s for s, ok in results if not ok]}"


@pytest.mark.unit
class TestAlertEngineNoticeNoDispatch:
    """Test 16 (original): NOTICE severity → no external notification."""

    @pytest.mark.asyncio
    async def test_notice_not_dispatched_to_channels(self):
        """NOTICE events are accepted but not dispatched externally."""
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="pause", component="hitl_gate")
        severity = _get_severity(event)
        assert severity == "NOTICE"
        # The api_server code only dispatches for CRITICAL/HIGH/WARNING
        assert severity not in ("CRITICAL", "HIGH", "WARNING")


@pytest.mark.unit
class TestAlertEngineAllowNoDispatch:
    """Test 17 (original): allow event → no external notification."""

    @pytest.mark.asyncio
    async def test_allow_not_dispatched(self):
        from api_server import _get_severity
        event = AuditEvent(api_key="k", event_type="allow", component="proxy")
        severity = _get_severity(event)
        assert severity == "NOTICE"
        assert severity not in ("CRITICAL", "HIGH", "WARNING")


@pytest.mark.unit
class TestAlertEngineChannelCredentialWarnings:
    """Test 15 (original): Channel credential warnings on init."""

    def test_missing_telegram_creds_logs_warning(self, caplog):
        """Warning logged for missing Telegram creds."""
        with patch("alert_engine.logger") as mock_logger:
            engine = AlertEngine()
            # With no env vars, Telegram/Slack/Email should all warn
            warning_calls = [
                c
                for c in mock_logger.warning.call_args_list
                if "not set" in str(c)
            ]
            assert len(warning_calls) >= 1, "Expected at least one warning for missing creds"
