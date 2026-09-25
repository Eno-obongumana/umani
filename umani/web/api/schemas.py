"""API schemas — the contract between frontend and backend.

Every request and response is defined here. If you change a field,
the frontend must be updated to match. This is the API surface.
"""
from typing import Optional
from pydantic import BaseModel, Field


# ─── Request models ──────────────────────────────

class ScanRequest(BaseModel):
    """Incoming request to POST /api/scan."""
    target: str = Field(..., description="URL to scan")
    cookie: Optional[str] = Field(
        None, description="Cookie header for authenticated scans")
    modules: Optional[list[str]] = Field(
        None, description="Subset of modules to run; None = all")


# ─── Response models ─────────────────────────────

class ModuleInfo(BaseModel):
    """One entry in GET /api/modules."""
    name: str
    severity: str
    description: str
    module_type: str


class FindingDTO(BaseModel):
    """One finding returned from a scan."""
    id: Optional[int] = None
    module: str
    name: str
    severity: str
    url: str
    param: Optional[str] = None
    evidence: str
    description: str
    remediation: str


class ScanResult(BaseModel):
    """Response from POST /api/scan."""
    scan_id: int
    target: str
    finding_count: int
    findings: list[FindingDTO]


class ScanSummary(BaseModel):
    """One entry in GET /api/scans."""
    id: int
    target: str
    started_at: Optional[str] = None
    finding_count: int


class ErrorResponse(BaseModel):
    """Standard error shape."""
    error: str
    detail: Optional[str] = None
