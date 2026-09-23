from ..core.requester import Requester
from ..core.plugin_loader import discover_modules
from .models import Finding


class Engine:
    def __init__(self, scope, datastore=None, options=None):
        self.scope = scope
        self.db = datastore
        self.options = options or {}
        self.requester = Requester(scope, datastore)
        self.modules = discover_modules()

    def scan(self, target: str, modules: list[str] | None = None,
             scan_id: int = 0) -> list[Finding]:
        self.scope.check(target)
        selected = modules or list(self.modules.keys())
        findings = []

        for name in selected:
            cls = self.modules.get(name)
            if not cls:
                continue
            mod = cls(self.requester, self.db, self.options.get(name, {}))
            try:
                results = mod.run(target)
                for f in results:
                    f.scan_id = scan_id
                    findings.append(f)
                    if self.db:
                        self.db.save_finding(f)
            except Exception as e:
                print(f"[!] module {name} failed: {e}")

        return findings
