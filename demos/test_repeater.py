from umani.core.scope import Scope
from umani.core.datastore import Datastore
from umani.core.engine import Engine
from umani.core.repeater import Repeater


def test_repeater_replays_with_modified_param(simple_flask, tmp_path):
    db_path = tmp_path / "test.db"
    store = Datastore(str(db_path))
    scan_id = store.new_scan(simple_flask, {})

    scope = Scope()
    engine = Engine(scope, store)
    engine.scan(f"{simple_flask}/user?id=1", modules=["sqli"],
                scan_id=scan_id)

    rows = store.list_findings(scan_id)
    assert len(rows) >= 1
    finding_id = rows[0]["id"]

    rep = Repeater(store, scope)
    result = rep.replay(finding_id, set_params={"id": "2"})

    assert result["new_response"]["status"] == 200
    assert result["new_response"]["length"] > 0
    assert result["finding"]["id"] == finding_id
