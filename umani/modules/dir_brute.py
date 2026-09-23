from pathlib import Path
from urllib.parse import urljoin
from ..core.models import Finding
from .base import Module


# Common 404 baseline: request a path we know doesn't exist, record its
# status/length. Any candidate matching that signature is considered a
# soft-404 and skipped.
CANARY_MISS = "umani_canary_does_not_exist_zzz"


class DirBruteModule(Module):
    name = "dir_brute"
    description = "Discover hidden paths and files"
    author = "you"
    severity = "info"

    # paths that indicate a real finding when present
    INTERESTING = {
        "admin": "medium",
        "backup": "medium",
        "config": "medium",
        ".git": "high",
        ".env": "critical",
        "wp-admin": "medium",
        "phpmyadmin": "high",
        "api": "info",
        "test": "info",
        "dev": "medium",
        "uploads": "info",
    }

    def _wordlist(self) -> list[str]:
        path = Path(__file__).parent.parent / "payloads" / "dirs.txt"
        if not path.exists():
            return ["admin", "login", "backup", ".git", ".env", "api"]
        return [line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def _baseline(self, base: str) -> tuple[int, int]:
        """Fetch a known-missing path. Its (status, length) becomes the
        soft-404 signature."""
        try:
            _, res = self.http.get(urljoin(base + "/", CANARY_MISS))
            return res.status, len(res.body)
        except Exception:
            return 404, 0

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not target.endswith("/"):
            target += "/"

        base_status, base_len = self._baseline(target)

        for word in self._wordlist():
            url = urljoin(target, word)
            try:
                req, res = self.http.get(url)
            except Exception:
                continue

            # soft-404 check: skip if identical to the known-missing path
            if (res.status == base_status
                    and abs(len(res.body) - base_len) < 50):
                continue

            # only report hits
            if res.status in (200, 301, 302, 401, 403):
                severity = self.INTERESTING.get(word, "info")
                findings.append(Finding(
                    name=f"Discovered: /{word} (HTTP {res.status})",
                    severity=severity,
                    url=url,
                    param=None,
                    evidence=(
                        f"Path: /{word}\n"
                        f"Status: {res.status}\n"
                        f"Length: {len(res.body)} bytes"
                    ),
                    description=(
                        f"The path /{word} exists and is not linked from the "
                        "main site. Hidden paths often expose admin panels, "
                        "backups, source control, or config files."
                    ),
                    remediation=(
                        "Remove or restrict access to non-public paths. "
                        "Never expose .git, .env, backups, or admin panels "
                        "without authentication."
                    ),
                    module=self.name,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))

        return findings
