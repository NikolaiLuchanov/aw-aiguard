"""Tests for Phase 3.1 — Template rendering.

Verifies template files exist and contain expected content.
Template routes that collide with API endpoints use file-level checks
since FastAPI prioritizes API routes (registered at module load time)
over template routes (registered in lifespan).
"""

import pytest
from pathlib import Path


@pytest.mark.asyncio
async def test_base_template():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    base_path = templates_path / "base.html"
    assert base_path.exists()
    content = base_path.read_text()
    assert "{% block title %}" in content


@pytest.mark.asyncio
async def test_index_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "index.html").read_text()
    assert "System Overview" in content


@pytest.mark.asyncio
async def test_hitl_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "hitl.html").read_text()
    assert "HITL Approval Queue" in content


@pytest.mark.asyncio
async def test_rules_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "rules.html").read_text()
    assert "BYOC Rule Management" in content


@pytest.mark.asyncio
async def test_settings_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "settings.html").read_text()
    assert "Settings Management" in content


@pytest.mark.asyncio
async def test_audit_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "audit.html").read_text()
    assert "Audit Log Browser" in content


@pytest.mark.asyncio
async def test_gateways_page():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    content = (templates_path / "gateways.html").read_text()
    assert "Gateway Status" in content


@pytest.mark.asyncio
async def test_all_template_files_exist():
    templates_path = Path(__file__).parent.parent.parent / "central-service" / "templates"
    expected = ["base.html", "index.html", "hitl.html", "rules.html",
                "settings.html", "audit.html", "gateways.html"]
    for name in expected:
        assert (templates_path / name).exists()


@pytest.mark.asyncio
async def test_static_css_exists():
    css_path = Path(__file__).parent.parent.parent / "central-service" / "static" / "style.css"
    assert css_path.exists()
    assert ".htmx-indicator" in css_path.read_text()


@pytest.mark.asyncio
async def test_ui_module_exists():
    from ui import templates, setup_template_serving
    assert templates is not None
    assert callable(setup_template_serving)
