from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from .base import Module


# Common DB error signatures — evidence the query broke
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query()",
    "postgresql.*error",
    "sqlite3.operationalerror",
    "sqlite error",
    "ora-01756",
    "ora-00933",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "syntax error in query expression",
]

# Error-based test payloads
ERROR_PAYLOADS = ["'", '"', "')", "';", "\\"]

# Boolean-based test pairs (true_payload, false_payload)
BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1) AND (1=1", "1) AND (1=2"),
]


class SqliModule(Module):
    name = "sqli"
    description = "Detect SQL injection (error-based + boolean-based)"
    author = "you"
    severity = "critical"

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _has_error_signature(self, body: bytes) -> str | None:
        text = body.decode("utf-8", errors="ignore").lower()
        for sig in ERROR_SIGNATURES:
            # crude regex match for sigs with .*
            if ".*" in sig:
                import re
                if re.search(sig, text):
                    return sig
            elif sig in text:
                return sig
        return None

    def _error_based(self, target: str, param: str) -> Finding | None:
        for payload in ERROR_PAYLOADS:
            test_url = self._inject(target, param, payload)
            try:
                req, res = self.http.get(test_url)
            except Exception:
                continue

            sig = self._has_error_signature(res.body)
            if sig:
                return Finding(
                    name=f"SQL injection (error-based) in '{param}'",
                    severity="critical",
                    url=test_url,
                    param=param,
                    evidence=(
                        f"Payload: {payload}\n"
                        f"DB error signature matched: '{sig}'"
                    ),
                    description=(
                        "The parameter is concatenated into a SQL query. "
                        "Injecting a quote breaks the query and the DB "
                        "returns an error, revealing the injection point."
                    ),
                    remediation=(
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input into SQL. "
                        "Suppress DB errors in production responses."
                    ),
                    module=self.name,
                    cvss=9.8,
                    scan_id=req.scan_id,
                    request_id=req.id,
                )
        return None

    def _boolean_based(self, target: str, param: str) -> Finding | None:
        for true_p, false_p in BOOLEAN_PAIRS:
            true_url = self._inject(target, param, true_p)
            false_url = self._inject(target, param, false_p)
            try:
                req_t, res_t = self.http.get(true_url)
                req_f, res_f = self.http.get(false_url)
            except Exception:
                continue

            # Same status, same length? not injectable this way.
            # Different length or status → strong signal of injection
            len_diff = abs(len(res_t.body) - len(res_f.body))
            status_diff = res_t.status != res_f.status

            if status_diff or len_diff > 20:
                return Finding(
                    name=f"SQL injection (boolean-based) in '{param}'",
                    severity="critical",
                    url=true_url,
                    param=param,
                    evidence=(
                        f"TRUE  payload: {true_p}  → status={res_t.status}, "
                        f"len={len(res_t.body)}\n"
                        f"FALSE payload: {false_p} → status={res_f.status}, "
                        f"len={len(res_f.body)}\n"
                        f"Difference: status_diff={status_diff}, "
                        f"len_diff={len_diff}"
                    ),
                    description=(
                        "The parameter changes query logic. TRUE and FALSE "
                        "payloads produce different responses, indicating "
                        "the input reaches the SQL engine unescaped."
                    ),
                    remediation=(
                        "Use parameterized queries. Never build SQL by "
                        "string concatenation."
                    ),
                    module=self.name,
                    cvss=9.8,
                    scan_id=req_t.scan_id,
                    request_id=req_t.id,
                )
        return None

    def run(self, target: str) -> list[Finding]:
        findings = []
        parsed = urlparse(target)
        params = list(parse_qs(parsed.query).keys())

        if not params:
            params = ["id", "q", "search", "user", "page", "cat"]

        for param in params:
            # try error-based first — it's cheaper and clearer
            f = self._error_based(target, param)
            if f:
                findings.append(f)
                continue

            f = self._boolean_based(target, param)
            if f:
                findings.append(f)

        return findings
