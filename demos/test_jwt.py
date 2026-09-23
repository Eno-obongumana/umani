import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="jwt")

from umani.core.scope import Scope
from umani.core.engine import Engine


def test_jwt_detects_weak_secret(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/api/me", modules=["jwt"])

    assert len(findings) >= 1
    names = [f.name for f in findings]
    assert any("weak secret" in n.lower() for n in names)

    weak = [f for f in findings if "weak secret" in f.name.lower()][0]
    assert weak.severity == "critical"
    assert "secret" in weak.evidence
