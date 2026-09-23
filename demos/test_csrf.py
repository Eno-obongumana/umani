from umani.core.scope import Scope
from umani.core.engine import Engine


def test_csrf_finds_vulnerable_form(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/profile", modules=["csrf"])

    assert len(findings) == 1
    f = findings[0]
    assert "csrf" in f.name.lower()
    assert f.url.endswith("/profile/update")
    assert f.severity == "medium"


def test_csrf_ignores_protected_form(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/password", modules=["csrf"])

    # the password form has a csrf_token field → no finding
    assert len(findings) == 0
