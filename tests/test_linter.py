"""
Static-analysis (linter) gate for aw-aiguard.

This test file enforces a *crash-level* lint gate so that regressions which
introduce real defects (undefined names, redefinitions, dead locals) fail the
suite. It deliberately does NOT gate on the ~400 stylistic ruff findings
(UP006/UP035 annotation style, F401 unused imports in re-exporting
__init__.py, BLE001 broad exceptions, etc.) — those are tracked in
``linter_audit.md`` and are out of scope for the automated gate.

Two checks are run:
  1. ``ruff`` with the pyflakes "crash-level" rule set:
       - F811 redefinition of unused name
       - F821 undefined name in ``__all__``
       - F822 undefined name in annotation
       - F823 local variable referenced before assignment
       - F841 local variable assigned but never used
  2. ``compileall`` (stdlib) — a full syntax/compile check of the source dirs.

The ruff check is skipped (not failed) if ``ruff`` is not importable in the
current interpreter, so the suite stays green in minimal environments while
still enforcing the gate wherever ruff is available.
"""

import pathlib
import subprocess
import sys

import pytest

# Resolve project root reliably (works regardless of pytest cwd)
_PROJECT_ROOT = pathlib.Path(__file__).parent.parent

# Source packages subject to the gate (tests/ is excluded on purpose).
_SOURCE_DIRS = ["gateway", "central-service", "shared", "tools"]

# Pyflakes rules that indicate a real defect (crash or dead code), not style.
_CRASH_RULES = ["F811", "F821", "F822", "F823", "F841"]


def _run(cmd):
    """Run a command list, returning a CompletedProcess (no raise)."""
    return subprocess.run(
        cmd,
        cwd=str(_PROJECT_ROOT),
        capture_output=True,
        text=True,
    )


def _ruff_available():
    """True if ``ruff`` can be run as a module in the current interpreter."""
    probe = _run([sys.executable, "-m", "ruff", "--version"])
    return probe.returncode == 0


@pytest.mark.skipif(
    not _ruff_available(),
    reason="ruff is not installed in the current interpreter "
    "(``.venv/bin/python -m pip install ruff`` to enable the lint gate)",
)
class TestRuffCrashGate:
    """The crash-level ruff gate must pass with zero findings."""

    def test_no_crash_level_findings(self):
        """Source dirs must be free of F8xx crash-level findings."""
        result = _run(
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                *_SOURCE_DIRS,
                "--select",
                ",".join(_CRASH_RULES),
                "--output-format",
                "concise",
            ]
        )
        assert result.returncode == 0, (
            "ruff found crash-level lint findings (undefined names, "
            "redefinitions, or dead locals):\n"
            f"{result.stdout}\n{result.stderr}"
        )


class TestSyntaxCompile:
    """Stdlib compile check — no external dependency, always runs."""

    def test_all_source_compiles(self):
        """Every source module must compile (no SyntaxError)."""
        result = _run(
            [sys.executable, "-m", "compileall", "-q", *_SOURCE_DIRS]
        )
        assert result.returncode == 0, (
            "compileall reported syntax/compile errors:\n"
            f"{result.stdout}\n{result.stderr}"
        )
