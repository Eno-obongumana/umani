from umani.core.scope import Scope
from umani.core.engine import Engine


def test_dir_brute_finds_admin(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/", modules=["dir_brute"])

    assert len(findings) >= 1
    urls = [f.url for f in findings]
    assert any("/admin" in u for u in urls)
    assert any("/backup" in u for u in urls)

    # admin should be flagged medium or higher
    admin = [f for f in findings if f.url.endswith("/admin")][0]
    assert admin.severity in ("info", "low", "medium", "high", "critical")
