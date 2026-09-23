from umani.core.scope import Scope
from umani.core.engine import Engine


def test_open_redirect_detects(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/redirect", modules=["open_redirect"])

    assert len(findings) >= 1
    f = findings[0]
    assert f.param == "url"
    assert f.severity == "medium"
    assert "umani-canary.example" in f.evidence
