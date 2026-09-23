from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from ..core.canary import Canary
from .base import Module


# Internal targets that indicate SSRF if the response includes their content
INTERNAL_TARGETS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
]

# Signatures that appear when we successfully read internal content
INTERNAL_SIGNATURES = [
    "ami-id", "instance-id", "iam/",        # AWS
    "computeMetadata",                       # GCP
    "127.0.0.1", "localhost",                # loopback
    "root:", "daemon:",                      # /etc/passwd style
]


class SsrfModule(Module):
    name = "ssrf"
    description = "Detect server-side request forgery"
    author = "you"
    severity = "high"

    def _params(self) -> list[str]:
        path = Path(__file__).parent.parent / "payloads" / "ssrf_params.txt"
        if not path.exists():
            return ["url", "uri", "path", "dest", "redirect", "src"]
        return [line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def run(self, target: str) -> list[Finding]:
        findings = []

        canary = Canary(host="127.0.0.1",)
        canary.start()

        try:
            params = self._params()

            # --- Canary-based detection ---
            for param in params:
                canary.clear()
                test_url = self._inject(target, param, canary.url)
                try:
                    req, res = self.http.get(test_url)
                except Exception:
                    continue

                if canary.hits():
                    findings.append(Finding(
                        name=f"SSRF (canary callback) via '{param}'",
                        severity="high",
                        url=test_url,
                        param=param,
                        evidence=(
                            f"Injected URL: {canary.url}\n"
                            f"Canary received {len(canary.hits())} hit(s) "
                            f"from {canary.hits()[0]['client']}"
                        ),
                        description=(
                            "The server made an outbound request to an "
                            "attacker-controlled URL supplied in the "
                            "parameter. This allows reaching internal "
                            "services, cloud metadata endpoints, and "
                            "possibly reading local files."
                        ),
                        remediation=(
                            "Validate and allowlist outbound destinations. "
                            "Block RFC1918 and link-local IPs. Disable "
                            "unused URL schemes. Use a proxy with strict "
                            "egress rules."
                        ),
                        module=self.name,
                        cvss=8.6,
                        scan_id=req.scan_id,
                        request_id=req.id,
                    ))
                    continue

                # --- Response-based detection (internal IPs) ---
                for internal in INTERNAL_TARGETS[:3]:  # only safe ones
                    internal_url = self._inject(target, param, internal)
                    try:
                        req2, res2 = self.http.get(internal_url)
                    except Exception:
                        continue
                    body = res2.body[:4096].decode("utf-8", errors="ignore")
                    if any(sig in body for sig in INTERNAL_SIGNATURES):
                        findings.append(Finding(
                            name=f"SSRF (internal response) via '{param}'",
                            severity="high",
                            url=internal_url,
                            param=param,
                            evidence=(
                                f"Injected URL: {internal}\n"
                                f"Response contained internal-content "
                                f"signature."
                            ),
                            description=(
                                "The server fetched an internal URL and "
                                "returned its content in the response."
                            ),
                            remediation=(
                                "Allowlist outbound destinations. Block "
                                "loopback and private IP ranges."
                            ),
                            module=self.name,
                            cvss=8.6,
                            scan_id=req2.scan_id,
                            request_id=req2.id,
                        ))
                        break

        finally:
            canary.stop()

        return findings
