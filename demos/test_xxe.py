from umani.core.scope import Scope
from umani.core.engine import Engine


def test_xxe_detects_file_disclosure(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/api/xml", modules=["xxe"])

    assert len(findings) >= 1
    names = [f.name for f in findings]
    assert any("file disclosure" in n.lower() for n in names)

    file_disc = [f for f in findings if "file disclosure" in f.name.lower()][0]
    assert file_disc.severity == "critical"
    assert "etc/passwd" in file_disc.evidence


def test_xxe_detects_ssrf_via_entity(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(f"{simple_flask}/api/xml", modules=["xxe"])

    names = [f.name for f in findings]
    assert any("SSRF" in n for n in names)
