import time
import httpx
from umani.core.scope import Scope
from umani.core.datastore import Datastore
from umani.core.proxy import Proxy


def test_proxy_passively_scans_traffic(simple_flask, tmp_path):
    """Proxy logs AND scans. After browsing, findings should be in the DB."""
    db_path = tmp_path / "passive.db"
    store = Datastore(str(db_path))
    scope = Scope()

    proxy = Proxy(store, scope, host="127.0.0.1", port=0)
    proxy.start()
    port = proxy._server.server_address[1]

    try:
        client = httpx.Client(proxy=f"http://127.0.0.1:{port}")
        r = client.get(f"{simple_flask}/")
        assert r.status_code == 200
    finally:
        # give passive scan threads a moment to finish
        time.sleep(2)
        proxy.stop()

    # The demo target has no security headers, so `headers` module
    # should have logged findings.
    cur = store.conn.execute("SELECT COUNT(*) FROM findings")
    count = cur.fetchone()[0]
    assert count >= 1, f"expected passive findings, got {count}"

    cur = store.conn.execute(
        "SELECT DISTINCT module FROM findings")
    modules_seen = {row[0] for row in cur.fetchall()}
    assert "headers" in modules_seen
