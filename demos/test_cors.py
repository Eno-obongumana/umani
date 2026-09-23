from umani.core.scope import Scope
from umani.core.engine import Engine


def test_cors_detects_reflection(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/api/cors", modules=["cors"])

    assert len(findings) >= 1
    names = [f.name for f in findings]
    assert any("reflection" in n.lower() for n in names)

    # the credentialed case should be high severity
    high = [f for f in findings if f.severity == "high"]
    assert len(high) >= 1
    assert "origin reflection" in high[0].name.lower()
