from urllib.parse import urljoin, urlparse, urldefrag
from bs4 import BeautifulSoup
from ..core.models import Finding
from .base import Module


class SpiderModule(Module):
    name = "spider"
    description = "Crawl the target and enumerate reachable URLs and forms"
    author = "you"
    severity = "info"

    def __init__(self, requester, datastore, options=None):
        super().__init__(requester, datastore, options)
        self.max_depth = self.options.get("depth", 2)
        self.max_urls = self.options.get("max_urls", 50)

    def _same_host(self, url: str, base: str) -> bool:
        return urlparse(url).hostname == urlparse(base).hostname

    def _normalize(self, url: str) -> str:
        url, _ = urldefrag(url)
        return url.rstrip("/")

    def run(self, target: str) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        queue: list[tuple[str, int]] = [(target, 0)]

        while queue and len(seen) < self.max_urls:
            url, depth = queue.pop(0)
            url = self._normalize(url)

            if url in seen or depth > self.max_depth:
                continue
            seen.add(url)

            try:
                req, res = self.http.get(url)
            except Exception:
                continue

            if "html" not in res.headers.get("content-type", "").lower():
                continue

            body = res.body.decode("utf-8", errors="ignore")
            soup = BeautifulSoup(body, "lxml")

            # collect links
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                if self._same_host(link, target):
                    findings.append(Finding(
                        name=f"Link found: {link}",
                        severity="info",
                        url=link,
                        param=None,
                        evidence=f"Discovered from {url}",
                        description="Internal link discovered during crawl.",
                        remediation="N/A — informational.",
                        module=self.name,
                        scan_id=req.scan_id,
                        request_id=req.id,
                    ))
                    if self._normalize(link) not in seen:
                        queue.append((link, depth + 1))

            # collect forms
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = (form.get("method") or "GET").upper()
                inputs = [i.get("name") for i in form.find_all("input")
                          if i.get("name")]
                findings.append(Finding(
                    name=f"Form found: {method} {urljoin(url, action)}",
                    severity="info",
                    url=urljoin(url, action),
                    param=",".join(inputs) if inputs else None,
                    evidence=(
                        f"Form on {url}\n"
                        f"Method: {method}\n"
                        f"Inputs: {inputs}"
                    ),
                    description=(
                        "HTML form discovered. Forms are candidate injection "
                        "points for XSS, SQLi, and CSRF testing."
                    ),
                    remediation="N/A — informational.",
                    module=self.name,
                    scan_id=req.scan_id,
                    request_id=req.id,
                ))

        return findings
