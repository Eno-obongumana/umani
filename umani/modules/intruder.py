from pathlib import Path
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from ..core.models import Finding
from .base import Module


# Anomaly thresholds
LENGTH_DIFF_THRESHOLD = 5       # bytes
TIME_DIFF_THRESHOLD = 1000       # ms


class IntruderModule(Module):
    name = "intruder"
    description = "Fuzz parameters with a payload list and detect anomalies"
    author = "you"
    severity = "medium"

    def __init__(self, requester, datastore, options=None):
        super().__init__(requester, datastore, options)
        # user must specify which param to fuzz via options
        self.param = self.options.get("param")
        self.wordlist = self.options.get("wordlist", "intruder_names.txt")

    def _load_payloads(self) -> list[str]:
        path = Path(__file__).parent.parent / "payloads" / self.wordlist
        if not path.exists():
            return ["admin", "test", "guest", "user"]
        return [line.strip() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith("#")]

    def _inject(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def _baseline(self, target: str, param: str) -> tuple[int, int, int]:
        """Send a random benign value as baseline."""
        url = self._inject(target, param, "umani_baseline_zzz")
        try:
            _, res = self.http.get(url)
            return res.status, len(res.body), res.elapsed_ms
        except Exception:
            return 0, 0, 0

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not self.param:
            return findings

        base_status, base_len, base_time = self._baseline(target, self.param)
        if base_status == 0:
            return findings

        payloads = self._load_payloads()

        for payload in payloads:
            url = self._inject(target, self.param, payload)
            try:
                req, res = self.http.get(url)
            except Exception:
                continue

            status_diff = res.status != base_status
            len_diff = abs(len(res.body) - base_len)
            time_diff = res.elapsed_ms - base_time

            # anomaly: different status, big length change, or slow response
            if (status_diff
                    or len_diff > LENGTH_DIFF_THRESHOLD
                    or time_diff > TIME_DIFF_THRESHOLD):

                reason = []
                if status_diff:
                    reason.append(f"status {base_status}→{res.status}")
                if len_diff > LENGTH_DIFF_THRESHOLD:
                    reason.append(f"length Δ{len_diff}")
                if time_diff > TIME_DIFF_THRESHOLD:
                    reason.append(f"time +{time_diff}ms")

                findings.append(Finding(
                    name=f"Intruder anomaly: '{payload}' on '{self.param}'",
                    severity="medium",
                    url=url,
                    param=self.param,
                    evidence=(
                        f"Payload: {payload}\n"
                        f"Baseline: status={base_status}, len={base_len}, "
                        f"time={base_time}ms\n"
                        f"Response: status={res.status}, "
                        f"len={len(res.body)}, time={res.elapsed_ms}ms\n"
                        f"Anomaly: {', '.join(reason)}"
                    ),
                    description=(
                        f"The payload '{payload}' produced a response that "
                        "differs from the baseline. This suggests the "
                        "parameter influences application logic in an "
                        "unexpected way."
                    ),
                    remediation=(
                        "Review the parameter handling. Different responses "
                        "for different inputs can indicate information "
                        "disclosure, injection, or access control issues."
                    ),
                    module=self.name,
                    cvss=5.3,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))

        return findings
