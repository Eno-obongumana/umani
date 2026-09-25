"""Service layer — business logic for scans.

This is where the real work happens: scope enforcement, running the
engine, calling modules. Routes call services; services call the
repository and the UMANI core.
"""
from typing import Optional
from ...core.scope import Scope, ScopeError
from ...core.engine import Engine
from ...core.plugin_loader import discover_modules
from ...core.reporter import Reporter
from .scan_repository import ScanRepository
from .schemas import FindingDTO, ModuleInfo, ScanResult


class ScanService:
    def __init__(self, db_path: str = "umani.db"):
        self.repo = ScanRepository(db_path)
        self.db_path = db_path

    # ─── Modules ──────────────────────────────────

    def list_modules(self) -> list[ModuleInfo]:
        mods = discover_modules()
        return [
            ModuleInfo(
                name=name,
                severity=cls.severity,
                description=cls.description,
                module_type=getattr(cls, "module_type", "active"),
            )
            for name, cls in sorted(mods.items())
        ]

    # ─── Scan ─────────────────────────────────────

    def run_scan(self, target: str,
                 modules: Optional[list[str]] = None,
                 cookie: Optional[str] = None) -> ScanResult:
        # 1. Enforce scope — this is where illegal targets get rejected
        scope = Scope()
        try:
            scope.check(target)
        except ScopeError as e:
            raise ValueError(str(e))

        # 2. Create the scan row in the DB
        scan_id = self.repo.create_scan(
            target, {"modules": modules, "cookie": bool(cookie)})

        # 3. Build the engine — this is the UMANI core
        from ...core.datastore import Datastore
        store = Datastore(self.db_path)
        engine = Engine(scope, store)

        # 4. Attach cookie if provided
        if cookie:
            engine.requester.client.headers["Cookie"] = cookie

        # 5. Run the scan — this is where modules fire
        findings = engine.scan(target, modules=modules, scan_id=scan_id)

        # 6. Convert to DTOs
        dtos = [
            FindingDTO(
                id=f.id,
                module=f.module,
                name=f.name,
                severity=f.severity,
                url=f.url,
                param=f.param,
                evidence=f.evidence,
                description=f.description,
                remediation=f.remediation,
            )
            for f in findings
        ]

        return ScanResult(
            scan_id=scan_id,
            target=target,
            finding_count=len(dtos),
            findings=dtos,
        )

    # ─── History ──────────────────────────────────

    def list_scans(self, limit: int = 100) -> list[dict]:
        scans = self.repo.list_scans(limit)
        for s in scans:
            s["finding_count"] = self.repo.count_findings(s["id"])
        return scans

    def get_findings(self, scan_id: int) -> list[dict]:
        scan = self.repo.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        return self.repo.get_findings(scan_id)

    # ─── Report ───────────────────────────────────

    def generate_report(self, scan_id: int, output_path: str) -> str:
        scan = self.repo.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        from ...core.datastore import Datastore
        store = Datastore(self.db_path)
        reporter = Reporter(store)
        reporter.write_html(scan_id, output_path)
        return output_path
