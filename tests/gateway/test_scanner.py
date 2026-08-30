"""Tests for gateway/core/scanner.py — PIIScanner."""

import pytest

from gateway.core.guardrail import SafetyDecision
from gateway.core.scanner import PIIScanner


@pytest.mark.unit
class TestPIIScanner:
    # --- Rule loading ---

    def test_load_real_rules(self, scan_rules_path):
        scanner = PIIScanner(rules_path=scan_rules_path)
        assert len(scanner.rules) == 8

    def test_load_missing_file_returns_empty(self, tmp_path):
        scanner = PIIScanner(rules_path=str(tmp_path / "nonexistent.yaml"))
        assert len(scanner.rules) == 0

    # --- AWS key detection (block) ---

    def test_aws_key_block(self, scan_rules_path):
        scanner = PIIScanner(
            rules_path=scan_rules_path,
            block_mode="block",
        )
        text = "my key is AKIAIOSFODNN7EXAMPLE"
        result, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.BLOCK

    def test_aws_key_warn_mode(self, scan_rules_path):
        """block_mode=warn downgrades block rules to WARNING."""
        scanner = PIIScanner(
            rules_path=scan_rules_path,
            block_mode="warn",
        )
        text = "my key is AKIAIOSFODNN7EXAMPLE"
        result, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.WARNING

    # --- Private key detection (block) ---

    def test_private_key_block(self, scan_rules_path):
        scanner = PIIScanner(rules_path=scan_rules_path)
        text = "-----BEGIN RSA PRIVATE KEY-----"
        _, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.BLOCK

    # --- Email redaction ---

    def test_email_redaction_token_mode(self, scan_rules_path):
        scanner = PIIScanner(
            rules_path=scan_rules_path,
            redaction_mode="token",
        )
        text = "contact user@example.com for help"
        result, decision = scanner.scan_text(text)
        assert "[GENERIC_EMAIL_1]" in result
        assert decision == SafetyDecision.ALLOW

    def test_email_redaction_mask_mode(self, scan_rules_path):
        scanner = PIIScanner(
            rules_path=scan_rules_path,
            redaction_mode="mask",
        )
        text = "contact user@example.com for help"
        result, decision = scanner.scan_text(text)
        # mask mode: first 4 + **** + last 4 of matched email
        assert "****" in result
        assert "user@example.com" not in result
        assert decision == SafetyDecision.ALLOW

    # --- Clean text ---

    def test_clean_text_passes(self, scan_rules_path):
        scanner = PIIScanner(rules_path=scan_rules_path)
        text = "This is a harmless prompt with no secrets."
        result, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.ALLOW
        assert result == text

    def test_empty_text(self, scan_rules_path):
        scanner = PIIScanner(rules_path=scan_rules_path)
        result, decision = scanner.scan_text("")
        assert result == ""
        assert decision == SafetyDecision.ALLOW

    def test_none_like_input(self, scan_rules_path):
        scanner = PIIScanner(rules_path=scan_rules_path)
        result, decision = scanner.scan_text(None)  # type: ignore
        assert decision == SafetyDecision.ALLOW

    # --- Multiple redactions ---

    def test_multiple_email_redactions(self, scan_rules_path):
        scanner = PIIScanner(
            rules_path=scan_rules_path,
            redaction_mode="token",
        )
        text = "email a@b.com and c@d.com"
        result, decision = scanner.scan_text(text)
        assert "[GENERIC_EMAIL_1]" in result
        assert "[GENERIC_EMAIL_2]" in result
        assert decision == SafetyDecision.ALLOW

    # --- Custom rules via temp fixture ---

    def test_custom_warn_rule(self, temp_scan_rules):
        rules = [
            {"name": "test_warn", "pattern": "DANGER", "action": "warn"},
        ]
        scanner = PIIScanner(rules_path=temp_scan_rules(rules))
        _, decision = scanner.scan_text("DANGER ahead")
        assert decision == SafetyDecision.WARNING

    def test_custom_ignore_rule(self, temp_scan_rules):
        rules = [
            {"name": "test_ignore", "pattern": "SAFE_WORD", "action": "ignore"},
        ]
        scanner = PIIScanner(rules_path=temp_scan_rules(rules))
        _, decision = scanner.scan_text("SAFE_WORD here")
        assert decision == SafetyDecision.ALLOW

    def test_block_takes_precedence_over_redact(self, temp_scan_rules):
        """Block rule short-circuits before redaction."""
        rules = [
            {"name": "block_rule", "pattern": "BLOCKME", "action": "block"},
            {"name": "redact_rule", "pattern": "user@domain.com", "action": "redact"},
        ]
        scanner = PIIScanner(rules_path=temp_scan_rules(rules))
        _, decision = scanner.scan_text("BLOCKME user@domain.com")
        assert decision == SafetyDecision.BLOCK

    # --- Redaction mode edge case ---

    def test_mask_mode_short_value(self, temp_scan_rules):
        """Values <= 8 chars are fully masked."""
        rules = [
            {"name": "short_secret", "pattern": "SHORT", "action": "redact"},
        ]
        scanner = PIIScanner(
            rules_path=temp_scan_rules(rules),
            redaction_mode="mask",
        )
        result, _ = scanner.scan_text("here is SHORT done")
        assert "*****" in result
        assert "SHORT" not in result

    # --- Settings wiring (Finding #7) ---

    def test_block_mode_map_hard_block(self):
        """_BLOCK_MODE_MAP: hard_block → block."""
        assert PIIScanner._BLOCK_MODE_MAP["hard_block"] == "block"

    def test_block_mode_map_soft_block(self):
        """_BLOCK_MODE_MAP: soft_block → warn."""
        assert PIIScanner._BLOCK_MODE_MAP["soft_block"] == "warn"

    def test_block_mode_map_disabled(self):
        """_BLOCK_MODE_MAP: disabled → ignore."""
        assert PIIScanner._BLOCK_MODE_MAP["disabled"] == "ignore"

    def test_scanner_hard_block_mode(self, scan_rules_path):
        """PIIScanner with hard_block mode enforces blocks."""
        scanner = PIIScanner(rules_path=scan_rules_path, block_mode="block")
        text = "my key is AKIAIOSFODNN7EXAMP01"
        _, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.BLOCK

    def test_scanner_soft_block_mode(self, scan_rules_path):
        """PIIScanner with soft_block (warn) downgrades block rules."""
        scanner = PIIScanner(rules_path=scan_rules_path, block_mode="warn")
        text = "my key is AKIAIOSFODNN7EXAMP01"
        _, decision = scanner.scan_text(text)
        assert decision == SafetyDecision.WARNING

    def test_scanner_disabled_mode(self, temp_scan_rules):
        """PIIScanner with ignore mode skips block actions."""
        rules = [
            {"name": "aws_key", "pattern": "AKIA[A-Z0-9]{16}", "action": "block"},
        ]
        scanner = PIIScanner(rules_path=temp_scan_rules(rules), block_mode="ignore")
        text = "my key is AKIAIOSFODNN7EXAMPLE"
        result, decision = scanner.scan_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" in result  # not redacted
        assert decision == SafetyDecision.ALLOW  # not blocked
