"""
Regression tests for finding #4: the central-service URL must come from
CENTRAL_SERVICE_URL, not be derived from GUARDIAN_URL.

These run in a SUBPROCESS on purpose: importing gateway/main.py re-runs every
component constructor (PIIScanner, HITLGate, BYOCEngine, SchemaValidator, ...),
so an in-session importlib.reload() would rebuild proxy_engine/audit_logger and
disturb other tests' module-level references (e.g. test_wiring.py). A fresh
interpreter is safe and fast (~1 s). load_dotenv(override=False) in main.py
means pre-set env vars win over gateway/.env.

IMPORTANT: _probe neutralizes BYOC_CLOUD_URL, HITL_CLOUD_URL,
CENTRAL_SERVICE_URL, and GUARDIAN_URL to "" so that load_dotenv(override=False)
doesn't let .env values interfere with the assertions. extra_env then
overrides these neutralized values for the specific test scenario.
"""
import os
import subprocess
import sys
import textwrap

GATEWAY_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "gateway")
PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", "..", "venv", "bin", "python")

# Pass PROJECT_ROOT as sys.argv[1] so the subprocess can resolve paths without __file__
PROBE = textwrap.dedent(
    """
    import os, sys
    # sys.argv[0] = '-c', sys.argv[1] = PROJECT_ROOT (passed by _probe)
    project_root = sys.argv[1]
    sys.path.insert(0, project_root)
    sys.path.insert(0, os.path.join(project_root, 'gateway'))
    import main
    print(main.CENTRAL_SERVICE_URL)
    print(main.audit_logger.backend_url)
    print(main.HITL_CLOUD_URL)
    print(main.BYOC_CLOUD_URL)
    """
)


def _probe(extra_env=None, drop=()):
    env = {k: v for k, v in os.environ.items() if k not in drop}
    # Force-neutralize these vars so .env values (loaded by load_dotenv)
    # cannot leak into the subprocess. extra_env then overrides only the
    # keys the test actually wants to set.
    env["BYOC_CLOUD_URL"] = ""
    env["HITL_CLOUD_URL"] = ""
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [VENV_PYTHON, "-c", PROBE, PROJECT_ROOT],
        cwd=GATEWAY_DIR, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    values = [l for l in result.stdout.splitlines() if l.startswith("http")]
    return result.stdout, values


def test_central_service_url_is_explicit():
    """All central-service consumers must equal CENTRAL_SERVICE_URL, not dirname(GUARDIAN_URL)."""
    _, (central, audit, hitl, byoc) = _probe({
        "CENTRAL_SERVICE_URL": "http://central:8000",
        "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
    })
    assert central == "http://central:8000"
    assert audit == "http://central:8000"
    assert hitl == "http://central:8000"
    assert byoc == "http://central:8000"
    # Must NOT have silently derived from the guardian host.
    assert audit != "http://localhost:8080"


def test_byoc_cloud_url_defaults_to_central_service_url():
    """BYOC_CLOUD_URL is a deprecated override; unset -> CENTRAL_SERVICE_URL."""
    _, (central, audit, hitl, byoc) = _probe({
        "CENTRAL_SERVICE_URL": "http://central:8000",
        "GUARDIAN_URL": "http://localhost:8080/v1/chat/completions",
    })
    assert byoc == central


def test_central_service_url_required():
    """Missing CENTRAL_SERVICE_URL must exit non-zero with an error message."""
    env = {k: v for k, v in os.environ.items()}
    # Force neutralize so .env can't provide a value
    for k in ("BYOC_CLOUD_URL", "HITL_CLOUD_URL", "CENTRAL_SERVICE_URL"):
        env[k] = ""
    result = subprocess.run(
        [VENV_PYTHON, "-c", PROBE, PROJECT_ROOT],
        cwd=GATEWAY_DIR, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode != 0
    combined = (result.stdout + result.stderr)
    assert "CENTRAL_SERVICE_URL" in combined


def test_guardian_url_required():
    """GUARDIAN_URL has no code default anymore - missing it must exit non-zero."""
    env = {k: v for k, v in os.environ.items() if k != "GUARDIAN_URL"}
    # Neutralize GUARDIAN_URL so .env doesn't provide a fallback value
    env.setdefault("GUARDIAN_URL", "")
    # Also neutralize the other keys that main.py reads from .env
    for k in ("BYOC_CLOUD_URL", "HITL_CLOUD_URL", "CENTRAL_SERVICE_URL"):
        env.setdefault(k, "")
    result = subprocess.run(
        [VENV_PYTHON, "-c", PROBE, PROJECT_ROOT],
        cwd=GATEWAY_DIR, capture_output=True, text=True, env=env, timeout=60,
    )
    assert result.returncode != 0
    assert "GUARDIAN_URL" in (result.stdout + result.stderr)
