from umani.core.scope import Scope
from umani.core.engine import Engine


def test_headers_finds_missing(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(simple_flask, modules=["headers"])

    names = [f.name for f in findings]
    assert any("Content-Security-Policy" in n for n in names)
    assert any("Strict-Transport-Security" in n for n in names)
    assert all(f.severity in ("info", "low", "medium", "high", "critical")
               for f in findings)
