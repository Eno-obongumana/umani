from ..core.models import Finding
from .base import Module


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "No CSP set. The browser has no policy to restrict "
                       "script/style/iframe sources, making XSS easier.",
        "remediation": "Define a Content-Security-Policy header with a "
                       "restrictive default-src.",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "No HSTS. Users can be downgraded to HTTP.",
        "remediation": "Set Strict-Transport-Security: max-age=31536000; "
                       "includeSubDomains.",
    },
    "X-Frame-Options": {
        "severity": "low",
        "description": "Missing X-Frame-Options. Page may be clickjackable.",
        "remediation": "Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP "
                       "frame-ancestors.",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "Missing X-Content-Type-Options: nosniff. MIME "
                       "sniffing may allow content-type confusion.",
        "remediation": "Set X-Content-Type-Options: nosniff.",
    },
    "Referrer-Policy": {
        "severity": "info",
        "description": "No Referrer-Policy. URLs may leak in the Referer "
                       "header to third parties.",
        "remediation": "Set Referrer-Policy: strict-origin-when-cross-origin "
                       "or no-referrer.",
    },
    "Permissions-Policy": {
        "severity": "info",
        "description": "No Permissions-Policy. Browser features are not "
                       "restricted.",
        "remediation": "Set a Permissions-Policy restricting unused features.",
    },
}


class HeadersModule(Module):
    name = "headers"
    description = "Audit HTTP security headers"
    author = "you"
    severity = "medium"
    module_type = "passive"

    def run(self, target: str) -> list[Finding]:
        req, res = self.http.get(target)
        findings = []
        present = {k.lower() for k in res.headers.keys()}

        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in present:
                findings.append(Finding(
                    name=f"Missing {header}",
                    severity=meta["severity"],
                    url=target,
                    param=None,
                    evidence=f"Header {header} not present in response",
                    description=meta["description"],
                    remediation=meta["remediation"],
                    module=self.name,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))
        return findings
