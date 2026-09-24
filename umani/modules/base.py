from abc import ABC, abstractmethod
from ..core.models import Finding


class Module(ABC):
    name: str = "base"
    description: str = ""
    author: str = ""
    severity: str = "info"
    module_type: str = "active"   # "active" | "passive"

    def __init__(self, requester, datastore, options: dict | None = None):
        self.http = requester
        self.db = datastore
        self.options = options or {}

    @abstractmethod
    def run(self, target: str) -> list[Finding]:
        """Run the check against target. Return findings."""
        ...
