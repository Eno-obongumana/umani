from ..core.models import Finding
from .base import Module


class CorsModule(Module):
    name = "cors"
    description = "Detect permissive CORS configurations"
    author = "you"
    severity = "medium"
    module_type = "passive"
    module_type = "passive"

    def run(self, target: str) -> list[Finding]:
        findings = []
        evil_origin = "https://umani-test.example"

        # Step 1: send a request with an attacker-controlled Origin header
        req, res = self.http.get(target, headers={"Origin": evil_origin})

        acao = res.headers.get("access-control-allow-origin", "")
        acac = res.headers.get("access-control-allow-credentials", "").lower()

        # Case 1: wildcard origin
        if acao == "*":
            findings.append(Finding(
                name="CORS: wildcard origin",
                severity="low",
                url=target,
                param=None,
                evidence="Access-Control-Allow-Origin: *",
                description=(
                    "The server allows any origin via a wildcard. "
                    "Browsers block credentialed requests with a wildcard, "
                    "so impact is limited to reading public data."
                ),
                remediation=(
                    "Restrict Access-Control-Allow-Origin to a specific "
                    "allowlist of trusted origins."
                ),
                module=self.name,
                scan_id=req.scan_id,
                request_id=req.id,
            ))

        # Case 2: origin reflection + credentials
        elif acao == evil_origin and acac == "true":
            findings.append(Finding(
                name="CORS: origin reflection with credentials",
                severity="high",
                url=target,
                param=None,
                evidence=(
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: true"
                ),
                description=(
                    "The server reflects the request Origin back and allows "
                    "credentials. Any site can read authenticated responses "
                    "from this endpoint on behalf of a logged-in user."
                ),
                remediation=(
                    "Validate the Origin against a strict allowlist. Never "
                    "reflect arbitrary origins when credentials are allowed."
                ),
                module=self.name,
                cvss=7.1,
                scan_id=req.scan_id,
                request_id=req.id,
            ))

        # Case 3: origin reflection without credentials
        elif acao == evil_origin:
            findings.append(Finding(
                name="CORS: origin reflection",
                severity="medium",
                url=target,
                param=None,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                description=(
                    "The server reflects the request Origin back. Without "
                    "credentials this leaks unauthenticated data to any site."
                ),
                remediation=(
                    "Validate the Origin against an allowlist instead of "
                    "reflecting it."
                ),
                module=self.name,
                scan_id=req.scan_id,
                request_id=req.id,
            ))

        return findings
