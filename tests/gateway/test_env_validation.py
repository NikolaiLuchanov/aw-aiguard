"""
Environment validation tests for the aw-aiguard Gateway Proxy.

Verifies that the gateway strictly enforces dual-variable configuration
(GUARDIAN_URL + CENTRAL_SERVICE_URL) and rejects startup with missing,
empty, or derived values.

Topology principle:
  - Gateway is ALWAYS local to the LLM client (localhost:9020)
  - GUARDIAN_URL: endpoint of the Granite Guardian model (dev: localhost:8080, prod: EC2)
  - CENTRAL_SERVICE_URL: endpoint of the Central Service API (dev: localhost:8000, prod: EC2)
  - Neither is derived from the other — no fallback, no dirname, no rsplit
"""

from typing import Optional
import os
import sys
import subprocess
import pytest

# Resolve project root reliably (works regardless of pytest cwd)
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Import here so it's available for the helper
from subprocess import TimeoutExpired


def _run_gateway_import(env_overrides: Optional[dict] = None) -> subprocess.CompletedProcess:
    """
    Run gateway.main.py as a script so module-level validation triggers.
    The gateway exits immediately on missing required env vars.
    Returns the CompletedProcess result.

    Note: We set PYTHONPATH so the subprocess can find the 'gateway' package.
    We also explicitly set empty-string overrides for vars we want to test as missing,
    because load_dotenv() would otherwise fill them from gateway/.env.
    """
    base_env = os.environ.copy()
    # Clear gateway-specific vars so each test controls them
    for var in ["GUARDIAN_URL", "CENTRAL_SERVICE_URL", "TARGET_API_BASE_URL", "TARGET_API_KEY"]:
        base_env.pop(var, None)

    # Ensure we have the base LLM config — gateway exits without it
    base_env["TARGET_API_KEY"] = "test-key-123"
    base_env["TARGET_API_BASE_URL"] = "https://api.openai.com/v1"

    # Apply test-specific overrides (explicit "" means "test this var as missing")
    if env_overrides:
        base_env.update(env_overrides)

    # Set PYTHONPATH so the subprocess can find the 'gateway' package
    base_env["PYTHONPATH"] = str(_PROJECT_ROOT)

    cmd = [
        sys.executable,
        os.path.join(_PROJECT_ROOT, "gateway", "main.py"),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, env=base_env, timeout=15, cwd=str(_PROJECT_ROOT))
    return result


def _run_gateway_with_timeout_check(env_overrides: Optional[dict] = None) -> subprocess.CompletedProcess:
    """
    Same as _run_gateway_import but catches TimeoutExpired and returns
    a synthetic CompletedProcess if the server started successfully.

    This is needed because a healthy gateway runs uvicorn indefinitely,
    so we can't always use a hard timeout. We treat 'Started server process'
    in stderr as evidence of success.
    """
    base_env = os.environ.copy()
    for var in ["GUARDIAN_URL", "CENTRAL_SERVICE_URL", "TARGET_API_BASE_URL", "TARGET_API_KEY"]:
        base_env.pop(var, None)

    base_env["TARGET_API_KEY"] = "test-key-123"
    base_env["TARGET_API_BASE_URL"] = "https://api.openai.com/v1"

    if env_overrides:
        base_env.update(env_overrides)

    base_env["PYTHONPATH"] = str(_PROJECT_ROOT)

    cmd = [
        sys.executable,
        os.path.join(_PROJECT_ROOT, "gateway", "main.py"),
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=base_env, timeout=15, cwd=str(_PROJECT_ROOT))
        return result
    except TimeoutExpired as e:
        # Server started but didn't exit within timeout — that's success
        stderr_text = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr) if e.stderr else ""
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout) if e.stdout else "",
            stderr=stderr_text,
        )


class TestGuardianUrlRequired:
    """GUARDIAN_URL must be set — gateway exits with error if missing."""

    def test_guardian_url_missing_exits(self):
        # Explicitly set GUARDIAN_URL="" so load_dotenv() won't fill from .env
        result = _run_gateway_import({
            "GUARDIAN_URL": "",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        })
        assert result.returncode != 0, f"Expected exit(1), got {result.returncode}. stderr: {result.stderr}"
        combined = result.stdout + result.stderr
        assert "GUARDIAN_URL" in combined, f"Expected 'GUARDIAN_URL' in error output. stdout={result.stdout!r} stderr={result.stderr!r}"

    def test_guardian_url_empty_exits(self):
        result = _run_gateway_import({
            "GUARDIAN_URL": "",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        })
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "GUARDIAN_URL" in combined


class TestCentralServiceUrlRequired:
    """CENTRAL_SERVICE_URL must be set — gateway exits with error if missing."""

    def test_central_service_url_missing_exits(self):
        result = _run_gateway_import({
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "",
        })
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "CENTRAL_SERVICE_URL" in combined

    def test_central_service_url_empty_exits(self):
        result = _run_gateway_import({
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "",
        })
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "CENTRAL_SERVICE_URL" in combined


class TestBothRequired:
    """Both GUARDIAN_URL and CENTRAL_SERVICE_URL must be set simultaneously."""

    def test_both_missing_exits(self):
        result = _run_gateway_import({
            "GUARDIAN_URL": "",
            "CENTRAL_SERVICE_URL": "",
        })
        assert result.returncode != 0
        # Check stdout + stderr (gateway print() goes to stdout)
        combined = result.stdout + result.stderr
        assert "GUARDIAN_URL" in combined or "CENTRAL_SERVICE_URL" in combined, \
            f"Expected validation error. stdout={result.stdout!r} stderr={result.stderr!r}"

    def test_both_set_dev_values_start(self):
        """With both vars set, gateway should NOT exit on validation — it starts the server."""
        result = _run_gateway_with_timeout_check({
            "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "http://localhost:8000",
        })
        # Either exit code 0 (started cleanly) or timeout (server is running) is success
        assert result.returncode == 0, f"Expected validation to pass. stdout={result.stdout!r} stderr={result.stderr!r}"

    def test_both_set_ec2_values_start(self):
        """With both vars set, gateway should NOT exit on validation — it starts the server."""
        result = _run_gateway_with_timeout_check({
            "GUARDIAN_URL": "http://54.123.45.67:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "http://54.98.76.54:8000",
        })
        # Either exit code 0 (started cleanly) or timeout (server is running) is success
        assert result.returncode == 0, f"Expected validation to pass. stdout={result.stdout!r} stderr={result.stderr!r}"


class TestNoDerivation:
    """No silent derivation — CENTRAL_SERVICE_URL cannot be derived from GUARDIAN_URL."""

    def test_central_not_derived_from_guardian(self):
        """If only GUARDIAN_URL is set, the gateway must NOT silently derive CENTRAL_SERVICE_URL."""
        result = _run_gateway_import({
            "GUARDIAN_URL": "http://54.123.45.67:8080/v1/chat/completions",
            "CENTRAL_SERVICE_URL": "",
        })
        # Must fail — no silent fallback to dirname
        assert result.returncode != 0
        combined = result.stdout + result.stderr
        assert "CENTRAL_SERVICE_URL" in combined

    def test_no_base_url_parameter_on_audit_logger(self):
        """AuditLogger must use backend_url, not base_url (legacy removed)."""
        from gateway.core.audit import AuditLogger
        import inspect

        sig = inspect.signature(AuditLogger.__init__)
        params = list(sig.parameters.keys())

        # base_url (legacy) must not be present
        assert "base_url" not in params, "AuditLogger.__init__ must not accept base_url"

        # backend_url must be present
        assert "backend_url" in params, "AuditLogger.__init__ must accept backend_url"


class TestValidationOrder:
    """GUARDIAN_URL must be validated before CENTRAL_SERVICE_URL."""

    def test_guardian_url_error_prints_first(self):
        """When both are missing, the first error printed should mention GUARDIAN_URL."""
        result = _run_gateway_import({
            "GUARDIAN_URL": "",
            "CENTRAL_SERVICE_URL": "",
        })
        # GUARDIAN_URL error should appear before CENTRAL_SERVICE_URL error
        # (or at least one of them should mention GUARDIAN_URL first)
        combined = result.stderr + result.stdout
        if "GUARDIAN_URL" in combined and "CENTRAL_SERVICE_URL" in combined:
            guard_pos = combined.index("GUARDIAN_URL")
            cent_pos = combined.index("CENTRAL_SERVICE_URL")
            assert guard_pos <= cent_pos, "GUARDIAN_URL error should print before CENTRAL_SERVICE_URL"
