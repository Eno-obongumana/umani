from umani.core.scope import Scope
from umani.core.engine import Engine


def test_log4shell_detects_canary_callback(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/log", modules=["log4shell"])

    assert len(findings) >= 1
    f = findings[0]
    assert f.severity == "critical"
    assert "Log4Shell" in f.name
    assert "jndi" in f.evidence.lower()
    assert "canary" in f.evidence.lower()
