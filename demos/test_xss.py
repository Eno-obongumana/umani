from umani.core.scope import Scope
from umani.core.engine import Engine


def test_xss_detects_reflection(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/search?q=test", modules=["xss"])

    assert len(findings) >= 1
    f = findings[0]
    assert f.param == "q"
    assert f.severity == "high"
    assert "umani_xss_marker" in f.evidence
