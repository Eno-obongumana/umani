from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from .base import Module


# Common redirect parameter names
REDIRECT_PARAMS = [
    "url", "next", "redirect", "return", "returnurl", "return_url",
    "redirect_uri", "redirect_url", "dest", "destination", "target",
    "r", "u", "to", "out", "view", "link", "goto", "continue",
]

# Canary — a domain that is clearly not the target
CANARY = "https://umani-canary.example"


class OpenRedirectModule(Module):
    name = "open_redirect"
    description = "Detect open redirect vulnerabilities"
    author = "you"
    severity = "medium"

    def _build_test_url(self, url: str, param: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [CANARY]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def run(self, target: str) -> list[Finding]:
        findings = []

        # Test each candidate parameter on the target URL
        for param in REDIRECT_PARAMS:
            test_url = self._build_test_url(target, param)
            try:
                req, res = self.http.get(test_url)
            except Exception:
                continue

            evidence = None

            # Case 1: 3xx redirect to the canary
            if 300 <= res.status < 400:
                location = res.headers.get("location", "")
                if CANARY in location:
                    evidence = f"HTTP {res.status} → Location: {location}"

            # Case 2: meta refresh / JS redirect in body
            if not evidence:
                body = res.body[:4096].decode("utf-8", errors="ignore")
                if CANARY in body and ("location" in body.lower()
                                       or "refresh" in body.lower()):
                    evidence = f"Canary reflected in body: {CANARY}"

            if evidence:
                findings.append(Finding(
                    name=f"Open redirect via '{param}' parameter",
                    severity="medium",
                    url=test_url,
                    param=param,
                    evidence=evidence,
                    description=(
                        f"The '{param}' parameter controls a redirect to an "
                        "attacker-supplied URL. Used in phishing, it makes "
                        "malicious links appear to originate from your domain."
                    ),
                    remediation=(
                        "Validate redirect targets against an allowlist of "
                        "permitted destinations. Never redirect to raw user input."
                    ),
                    module=self.name,
                    cvss=4.7,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))
                # one finding per run is enough for the demo
                break

        return findings
