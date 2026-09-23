from dataclasses import dataclass, field
from datetime import datetime,timezone
from typing import Optional


@dataclass
class Request:
    id: Optional[int]
    scan_id: int
    method: str
    url: str
    headers: dict
    body: Optional[bytes]
created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class Response:
    id: Optional[int]
    request_id: int
    status: int
    headers: dict
    body: bytes
    elapsed_ms: int


@dataclass
class Finding:
    name: str
    severity: str          # info | low | medium | high | critical
    url: str
    param: Optional[str]
    evidence: str
    description: str
    remediation: str
    module: str
    cvss: Optional[float] = None
    references: list[str] = field(default_factory=list)
    scan_id: Optional[int] = None
    request_id: Optional[int] = None

