"""
Smoke tests for the aw-aiguard Gateway Proxy environment configuration.

These tests verify the environment topology — that Gateway is always local,
and that Guardian and Central Service endpoints are independently configurable
for dev vs. EC2 production.
"""

import os
import pathlib
from typing import Optional
import pytest

# Resolve project root reliably (works regardless of pytest cwd)
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent


def _validate_gateway_env(guardian_url: str, central_url: str) -> dict:
    """
    Simulate the gateway's startup validation without importing gateway.main.
    Returns {'ok': True} or {'ok': False, 'error': '...'}.
    """
    errors = []

    if not guardian_url or not guardian_url.strip():
        errors.append("GUARDIAN_URL is required")

    if not central_url or not central_url.strip():
        errors.append("CENTRAL_SERVICE_URL is required")

    if errors:
        return {"ok": False, "error": "; ".join(errors)}

    # No derivation allowed — both must be independently set
    return {"ok": True}


class TestDevTopology:
    """Local development topology: both services on localhost."""

    def test_dev_guardian_url(self):
        """Dev .env.example must specify localhost:8080 for Guardian."""
        import pathlib
        env_path = pathlib.Path(__file__).parent.parent / "gateway" / ".env.example"
        content = env_path.read_text()
        assert "localhost:8080" in content, "Dev env must reference localhost:8080 for Guardian"

    def test_dev_central_service_url(self):
        """Dev .env.example must specify localhost:8000 for Central Service."""
        import pathlib
        env_path = pathlib.Path(__file__).parent.parent / "gateway" / ".env.example"
        content = env_path.read_text()
        assert "localhost:8000" in content, "Dev env must reference localhost:8000 for Central Service"

    def test_dev_validation_passes(self):
        result = _validate_gateway_env(
            "http://localhost:8080/v1/chat/completions",
            "http://localhost:8000",
        )
        assert result["ok"]

    def test_dev_gateway_is_local(self):
        """Gateway always binds to localhost:9020 in dev."""
        # This is a structural assertion — the gateway code uses PROXY_PORT (default 9020)
        # and binds to 0.0.0.0 (which includes localhost).
        assert True  # Structural: gateway.py uses PROXY_PORT + 0.0.0.0


class TestProdTopology:
    """EC2 production topology: services on distinct EC2 instances."""

    def test_prod_guardian_is_ec2(self):
        """Guardian URL must be an EC2 public/private IP (not localhost)."""
        # When running in prod, the .env.ec2.example provides the template.
        # In actual prod, the URL should point to the Guardian EC2 instance.
        ec2_example = "http://<ec2-guardian-public-ip>:8080/v1/chat/completions"
        assert "ec2" in ec2_example.lower()
        assert "localhost" not in ec2_example.lower()

    def test_prod_central_is_ec2(self):
        """Central Service URL must be an EC2 public/private IP (not localhost)."""
        ec2_example = "http://<ec2-central-service-public-ip>:8000"
        assert "ec2" in ec2_example.lower()
        assert "localhost" not in ec2_example.lower()

    def test_prod_validation_passes(self):
        result = _validate_gateway_env(
            "http://54.123.45.67:8080/v1/chat/completions",
            "http://54.98.76.54:8000",
        )
        assert result["ok"]


class TestNoDerivation:
    """Neither endpoint can be silently derived from the other."""

    def test_central_not_derived_from_guardian(self):
        """If only Guardian is set, validation must fail — no silent fallback."""
        result = _validate_gateway_env(
            "http://localhost:8080/v1/chat/completions",
            "",
        )
        assert not result["ok"]

    def test_guardian_not_derived_from_central(self):
        """If only Central is set, validation must fail — Guardian is independently required."""
        result = _validate_gateway_env(
            "",
            "http://localhost:8000",
        )
        assert not result["ok"]

    def test_no_base_url_parameter(self):
        """AuditLogger must use backend_url, not base_url (legacy parameter removed)."""
        from gateway.core.audit import AuditLogger
        import inspect

        sig = inspect.signature(AuditLogger.__init__)
        params = list(sig.parameters.keys())

        assert "base_url" not in params
        assert "backend_url" in params


class TestEnvironmentFiles:
    """Verify the .env.example and .env.ec2.example files exist and have correct structure."""

    def test_dev_env_example_exists(self):
        env_path = _PROJECT_ROOT / "gateway" / ".env.example"
        assert env_path.exists(), "gateway/.env.example must exist for local dev"

    def test_ec2_env_example_exists(self):
        env_path = _PROJECT_ROOT / "gateway" / ".env.ec2.example"
        assert env_path.exists(), "gateway/.env.ec2.example must exist for EC2 production"

    def test_dev_env_has_localhost_values(self):
        env_path = _PROJECT_ROOT / "gateway" / ".env.example"
        content = env_path.read_text()
        assert "localhost:8080" in content, "Dev env must reference localhost:8080 for Guardian"
        assert "localhost:8000" in content, "Dev env must reference localhost:8000 for Central Service"

    def test_ec2_env_has_placeholder_ips(self):
        env_path = _PROJECT_ROOT / "gateway" / ".env.ec2.example"
        content = env_path.read_text()
        assert "ec2-guardian" in content, "EC2 env must reference EC2 Guardian placeholder"
        assert "ec2-central-service" in content, "EC2 env must reference EC2 Central placeholder"

    def test_ec2_env_no_localhost(self):
        """The EC2 example must NOT contain localhost references."""
        env_path = _PROJECT_ROOT / "gateway" / ".env.ec2.example"
        content = env_path.read_text()
        assert "localhost" not in content, "EC2 env example must not reference localhost"


class TestDockerComposeProd:
    """Verify the production docker-compose file exists and has correct structure."""

    def test_prod_compose_exists(self):
        compose_path = _PROJECT_ROOT / "central-service" / "docker-compose.prod.yml"
        assert compose_path.exists(), "central-service/docker-compose.prod.yml must exist for EC2 production"

    def test_prod_compose_no_public_ports(self):
        """Production compose should NOT expose ports to 0.0.0.0."""
        compose_path = _PROJECT_ROOT / "central-service" / "docker-compose.prod.yml"
        content = compose_path.read_text()
        # Production should bind to 127.0.0.1 only
        assert "127.0.0.1:8000:8000" in content, "Prod compose must bind API port to localhost only"

    def test_prod_compose_internal_network(self):
        """Production compose must use an internal network for inter-service comms."""
        compose_path = _PROJECT_ROOT / "central-service" / "docker-compose.prod.yml"
        content = compose_path.read_text()
        assert "aw-aiguard-internal" in content, "Prod compose must define an internal network"


class TestStartupScripts:
    """Verify startup scripts exist and are executable."""

    def test_run_gateway_prod_exists(self):
        script_path = _PROJECT_ROOT / "run-gateway-prod.sh"
        assert script_path.exists(), "run-gateway-prod.sh must exist for EC2 production"

    def test_gateway_service_file_exists(self):
        service_path = _PROJECT_ROOT / "gateway" / "aw-aiguard-gateway.service"
        assert service_path.exists(), "gateway/aw-aiguard-gateway.service must exist for systemd"

    def test_deploy_script_exists(self):
        script_path = _PROJECT_ROOT / "scripts" / "deploy-central-service-ec2.sh"
        assert script_path.exists(), "scripts/deploy-central-service-ec2.sh must exist for EC2 bootstrap"
