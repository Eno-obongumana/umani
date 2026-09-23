from umani.core.scope import Scope
from umani.core.engine import Engine


def test_spider_finds_links_and_forms(simple_flask):
    scope = Scope()
    engine = Engine(scope)
    findings = engine.scan(simple_flask, modules=["spider"])

    # find the link discovery for /about
    links = [f for f in findings if "Link found" in f.name]
    urls = [f.url for f in links]
    assert any("/about" in u for u in urls)
    assert any("/contact" in u for u in urls)

    # find the form on /contact
    forms = [f for f in findings if "Form found" in f.name]
    assert len(forms) >= 1
    assert any("name" in (f.param or "") for f in forms)
