"""
central-service/ui/__init__.py
Template serving utilities for the dashboard.

Template routes use /ui/* prefix to avoid collision with API endpoints
registered at module load time.
"""

from pathlib import Path

from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
STATIC_DIR = Path(__file__).parent.parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def setup_template_serving(app):
    """Mount template routes and static files on the FastAPI app.

    Template routes use /ui/* prefix to avoid collision with API endpoints
    registered at module load time.
    """
    # Serve static files (CSS, JS, images)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Dashboard pages — render templates
    from fastapi.responses import HTMLResponse

    @app.get("/ui/dashboard", response_class=HTMLResponse)
    async def dashboard_home(request):
        return templates.TemplateResponse("index.html", {"request": request})

    @app.get("/ui/hitl", response_class=HTMLResponse)
    async def dashboard_hitl(request):
        return templates.TemplateResponse("hitl.html", {"request": request})

    @app.get("/ui/rules", response_class=HTMLResponse)
    async def dashboard_rules(request):
        return templates.TemplateResponse("rules.html", {"request": request})

    @app.get("/ui/settings", response_class=HTMLResponse)
    async def dashboard_settings_page(request):
        return templates.TemplateResponse("settings.html", {"request": request})

    @app.get("/ui/audit", response_class=HTMLResponse)
    async def dashboard_audit(request):
        return templates.TemplateResponse("audit.html", {"request": request})

    @app.get("/ui/gateways", response_class=HTMLResponse)
    async def dashboard_gateways_page(request):
        return templates.TemplateResponse("gateways.html", {"request": request})
