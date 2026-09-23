from umani.core.scope import Scope
from umani.core.engine import Engine


def test_intruder_finds_anomaly(simple_flask):
    scope = Scope()
    engine = Engine(scope, options={"intruder": {"param": "name"}})
    findings = engine.scan(f"{simple_flask}/lookup?name=test",
                            modules=["intruder"])

    # should find at least one anomaly (admin returns different content)
    assert len(findings) >= 1
    names = [f.name for f in findings]
    assert any("admin" in n for n in names)

    # all findings should be medium
    assert all(f.severity == "medium" for f in findings)
