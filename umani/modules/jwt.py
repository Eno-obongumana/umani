import base64
import json
import re
from pathlib import Path
import jwt as pyjwt
from ..core.models import Finding
from .base import Module


JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")


class JwtModule(Module):
    name = "jwt"
    description = "Detect JWT weaknesses (alg:none, weak secret, expiry)"
    author = "you"
    severity = "high"
    module_type = "passive"

    def _load_secrets(self) -> list[str]:
        path = Path(__file__).parent.parent / "payloads" / "jwt_secrets.txt"
        if not path.exists():
            return ["secret", "password", "jwt", "key", "changeme"]
        return [line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def _find_jwt(self, body: bytes) -> str | None:
        text = body.decode("utf-8", errors="ignore")
        m = JWT_RE.search(text)
        return m.group(0) if m else None

    def _b64url_decode(self, s: str) -> bytes:
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad)

    def _decode_unverified(self, token: str) -> tuple[dict, dict]:
        header_b64, payload_b64, _ = token.split(".")
        header = json.loads(self._b64url_decode(header_b64))
        payload = json.loads(self._b64url_decode(payload_b64))
        return header, payload

    def run(self, target: str) -> list[Finding]:
        findings = []
        try:
            req, res = self.http.get(target)
        except Exception:
            return findings

        token = self._find_jwt(res.body)
        if not token:
            return findings

        try:
            header, payload = self._decode_unverified(token)
        except Exception:
            return findings

        # Check 1: alg:none
        if header.get("alg", "").lower() == "none":
            findings.append(Finding(
                name="JWT uses alg:none",
                severity="critical",
                url=target,
                param=None,
                evidence=f"Header: {header}",
                description=(
                    "The JWT is not signed (alg=none). Anyone can forge a "
                    "token with any claims by setting alg to 'none'."
                ),
                remediation=(
                    "Reject tokens with alg=none. Pin the expected algorithm "
                    "server-side; never trust the header's alg."
                ),
                module=self.name,
                cvss=9.1,
                scan_id=req.scan_id,
                request_id=req.id,
            ))

        # Check 2: weak HMAC secret
        if header.get("alg", "").upper() == "HS256":
            for secret in self._load_secrets():
                try:
                    pyjwt.decode(token, secret, algorithms=["HS256"])
                    findings.append(Finding(
                        name="JWT signed with weak secret",
                        severity="critical",
                        url=target,
                        param=None,
                        evidence=(
                            f"Secret recovered: '{secret}'\n"
                            f"Token: {token[:60]}…"
                        ),
                        description=(
                            "The JWT uses HS256 with a guessable secret. "
                            "Anyone with the secret can forge tokens for any "
                            "user or role."
                        ),
                        remediation=(
                            "Use a long random secret (>= 256 bits) or "
                            "switch to RS256/ES256 with proper key management."
                        ),
                        module=self.name,
                        cvss=9.1,
                        scan_id=req.scan_id,
                        request_id=req.id,
                    ))
                    break
                except pyjwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue

        # Check 3: expiry
        if not payload.get("exp"):
            findings.append(Finding(
                name="JWT has no expiry claim",
                severity="medium",
                url=target,
                param=None,
                evidence=f"Payload: {payload}",
                description=(
                    "The JWT has no 'exp' claim, so it never expires. "
                    "A leaked token is valid forever."
                ),
                remediation=(
                    "Always set an 'exp' claim (short lifetime) and verify "
                    "it server-side."
                ),
                module=self.name,
                cvss=5.3,
                scan_id=req.scan_id,
                request_id=req.id,
            ))

        return findings
