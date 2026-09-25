"""FastAPI application — HTTP routes only.

Routes are thin: they parse input, call the service, return JSON.
Business logic lives in api/scan_service.py.
Database access lives in api/scan_repository.py.
Request/response shapes live in api/schemas.py.
"""
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from .api.schemas import ScanRequest, ScanResult, ModuleInfo
from .api.scan_service import ScanService


WEB_DIR = Path(__file__).parent
TEMPLATE_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"
DB_PATH = "umani.db"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def create_app() -> FastAPI:
    app = FastAPI(
        title="UMANI API",
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )

    service = ScanService(DB_PATH)

    # ─── Static assets ────────────────────────────
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)),
              name="static")

    # ─── Frontend page ────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={},
        )

    # ─── Backend: modules list ────────────────────
    @app.get("/api/modules", response_model=list[ModuleInfo])
    def list_modules():
        return service.list_modules()

    # ─── Backend: run a scan ──────────────────────
    @app.post("/api/scan", response_model=ScanResult)
    def run_scan(req: ScanRequest):
        try:
            return service.run_scan(
                req.target, modules=req.modules, cookie=req.cookie)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

    # ─── Backend: scan history ────────────────────
    @app.get("/api/scans")
    def list_scans(limit: int = 100):
        return service.list_scans(limit=limit)

    @app.get("/api/scans/{scan_id}")
    def get_findings(scan_id: int):
        try:
            return service.get_findings(scan_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    # ─── Backend: report generation ───────────────
    @app.get("/report/{scan_id}")
    def serve_report(scan_id: int):
        try:
            out = service.generate_report(
                scan_id, f"report-{scan_id}.html")
            return FileResponse(out, media_type="text/html")
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    return app
