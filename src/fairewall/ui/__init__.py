"""Browser surfaces bundled with the Python package."""
from pathlib import Path

from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, Response

ASSETS = Path(__file__).parent


def mount_theme(app):
    app.mount("/ui/assets", StaticFiles(directory=ASSETS / "assets"), name="ui-assets")

    @app.get("/ui/theme.css", include_in_schema=False)
    def theme():
        return Response((ASSETS / "theme.css").read_text(encoding="utf-8"), media_type="text/css")


def mount_console(app, *, durable=False):
    mount_theme(app)

    @app.get("/console", response_class=HTMLResponse, include_in_schema=False)
    def console():
        page = (ASSETS / "console.html").read_text(encoding="utf-8")
        return HTMLResponse(page.replace("{{backend}}", "durable" if durable else "gateway"),
                            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"})
