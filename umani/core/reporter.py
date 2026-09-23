from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


SEVERITIES = ["critical", "high", "medium", "low", "info"]

TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


class Reporter:
    def __init__(self, datastore):
        self.db = datastore
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

    def _fetch_findings(self, scan_id: int) -> list[dict]:
        cur = self.db.conn.execute(
            "SELECT module, name, severity, url, param, evidence, "
            "description, remediation, cvss "
            "FROM findings WHERE scan_id=? "
            "ORDER BY CASE severity "
            "  WHEN 'critical' THEN 1 "
            "  WHEN 'high' THEN 2 "
            "  WHEN 'medium' THEN 3 "
            "  WHEN 'low' THEN 4 "
            "  ELSE 5 END",
            (scan_id,),
        )
        cols = ["module", "name", "severity", "url", "param",
                "evidence", "description", "remediation", "cvss"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def _fetch_target(self, scan_id: int) -> str:
        cur = self.db.conn.execute(
            "SELECT target FROM scans WHERE id=?", (scan_id,))
        row = cur.fetchone()
        return row[0] if row else "unknown"

    def render_html(self, scan_id: int) -> str:
        findings = self._fetch_findings(scan_id)
        target = self._fetch_target(scan_id)

        counts = {s: 0 for s in SEVERITIES}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        template = self.env.get_template("report.html.j2")
        return template.render(
            target=target,
            scan_id=scan_id,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            total=len(findings),
            counts=counts,
            findings=findings,
        )

    def write_html(self, scan_id: int, output_path: str | Path) -> Path:
        html = self.render_html(scan_id)
        out = Path(output_path)
        out.write_text(html, encoding="utf-8")
        return out
