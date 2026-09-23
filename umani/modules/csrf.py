from urllib.parse import urljoin
from bs4 import BeautifulSoup
from ..core.models import Finding
from .base import Module


# Common CSRF token field names
TOKEN_NAMES = (
    "csrf", "csrftoken", "csrf_token", "_csrf", "_token",
    "authenticity_token", "xsrf", "xsrf-token", "__requestverificationtoken",
    "anti-csrf", "anticsrf", "nonce",
)

# Methods that are considered state-changing
STATEFUL_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class CsrfModule(Module):
    name = "csrf"
    description = "Detect forms missing CSRF protection"
    author = "you"
    severity = "medium"

    def _has_token(self, form) -> bool:
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(t in name for t in TOKEN_NAMES):
                return True
        return False

    def run(self, target: str) -> list[Finding]:
        findings = []
        try:
            req, res = self.http.get(target)
        except Exception:
            return findings

        if "html" not in res.headers.get("content-type", "").lower():
            return findings

        body = res.body.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(body, "lxml")

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            if method not in STATEFUL_METHODS:
                continue

            action = form.get("action", target)
            action_url = urljoin(target, action)

            if not self._has_token(form):
                inputs = [i.get("name") for i in form.find_all("input")
                          if i.get("name")]
                findings.append(Finding(
                    name=f"CSRF: form at {action_url} missing token",
                    severity="medium",
                    url=action_url,
                    param=",".join(inputs) if inputs else None,
                    evidence=(
                        f"Form action: {action_url}\n"
                        f"Method: {method}\n"
                        f"Inputs: {inputs}\n"
                        f"No CSRF token field found."
                    ),
                    description=(
                        "This state-changing form does not include a CSRF "
                        "token. An attacker can force a logged-in user's "
                        "browser to submit this form silently."
                    ),
                    remediation=(
                        "Include a per-session, unpredictable CSRF token in "
                        "every state-changing form. Validate the token "
                        "server-side before processing the request. Also "
                        "set SameSite=Lax or Strict on session cookies."
                    ),
                    module=self.name,
                    cvss=6.5,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))

        return findings
