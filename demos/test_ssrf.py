from umani.core.scope import Scope
from umani.core.engine import Engine


def test_ssrf_detects_canary_callback(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/fetch", modules=["ssrf"])

    assert len(findings) >= 1
    names = [f.name for f in findings]
    assert any("SSRF" in n for n in names)
    assert any(f.severity == "high" for f in findings)

    canary_hit = [f for f in findings if "canary" in f.name.lower()]
    assert len(canary_hit) >= 1
    assert "param" in canary_hit[0].__dict__
    assert canary_hit[0].param == "url"
