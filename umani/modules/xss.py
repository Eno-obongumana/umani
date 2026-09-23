from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from .base import Module


# Payloads that are distinctive enough to detect reflection without
# triggering WAFs on benign labs. Each has a unique marker.
PAYLOADS = [
    '<umani_xss_marker>',
    '"><umani_xss_marker>',
    "'><umani_xss_marker>",
    '<script>umani_xss_marker</script>',
    'javascript:umani_xss_marker',
    '<img src=x onerror=umani_xss_marker>',
]

MARKER = "umani_xss_marker"


class XssModule(Module):
    name = "xss"
    description = "Detect reflected cross-site scripting"
    author = "you"
    severity = "high"

    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _is_reflected_unescaped(self, body: bytes, payload: str) -> bool:
        text = body.decode("utf-8", errors="ignore")
        # If the exact payload appears, it was NOT escaped by the server
        return payload in text

    def run(self, target: str) -> list[Finding]:
        findings = []
        parsed = urlparse(target)
        params = list(parse_qs(parsed.query).keys())

        # If no params, try common ones
        if not params:
            params = ["q", "search", "query", "s", "keyword", "id", "name"]

        for param in params:
            for payload in PAYLOADS:
                test_url = self._inject(target, param, payload)
                try:
                    req, res = self.http.get(test_url)
                except Exception:
                    continue

                if self._is_reflected_unescaped(res.body, payload):
                    findings.append(Finding(
                        name=f"Reflected XSS in '{param}'",
                        severity="high",
                        url=test_url,
                        param=param,
                        evidence=(
                            f"Payload: {payload}\n"
                            f"Reflected unescaped in response body."
                        ),
                        description=(
                            "User input is reflected in the response without "
                            "HTML encoding. An attacker can inject script that "
                            "executes in the victim's browser, stealing cookies, "
                            "tokens, or performing actions on their behalf."
                        ),
                        remediation=(
                            "HTML-encode all user input before inserting into "
                            "the response. Use context-aware escaping and a "
                            "strict Content-Security-Policy."
                        ),
                        module=self.name,
                        cvss=6.1,
                        scan_id=req.scan_id,
                        request_id=req.id,
                    ))
                    # one finding per parameter is enough for the demo
                    break

        return findings
