from pathlib import Path
from umani.core.scope import Scope
from umani.core.engine import Engine
from umani.core.datastore import Datastore
from umani.core.reporter import Reporter


def test_reporter_renders_findings(simple_flask, tmp_path):
    db_path = tmp_path / "test.db"
    store = Datastore(str(db_path))
    scan_id = store.new_scan(simple_flask, {})

    scope = Scope()
    engine = Engine(scope, store)
    engine.scan(simple_flask, modules=["headers"], scan_id=scan_id)

    reporter = Reporter(store)
    out = tmp_path / "report.html"
    reporter.write_html(scan_id, out)

    assert out.exists()
    html = out.read_text()
    assert "UMANI Security Report" in html
    assert "Content-Security-Policy" in html
    assert "Executive Summary" in html
