from umani.core.scope import Scope
from umani.core.engine import Engine


def test_sqli_detects(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/user?id=1", modules=["sqli"])

    assert len(findings) >= 1
    f = findings[0]
    assert f.param == "id"
    assert f.severity == "critical"
    assert "sql" in f.name.lower()
