import httpx
from umani.core.scope import Scope
from umani.core.datastore import Datastore
from umani.core.proxy import Proxy


def test_proxy_logs_traffic(simple_flask, tmp_path):
    db_path = tmp_path / "proxy.db"
    store = Datastore(str(db_path))
    scope = Scope()

    proxy = Proxy(store, scope, host="127.0.0.1", port=0)  # OS-assigned port
    proxy.start()
    port = proxy._server.server_address[1]

    try:
        client = httpx.Client(proxy=f"http://127.0.0.1:{port}")
        r = client.get(f"{simple_flask}/")
        assert r.status_code == 200
        assert "UMANI" in r.text or "demo" in r.text.lower()
    finally:
        proxy.stop()

    # confirm the request was logged
    cur = store.conn.execute("SELECT COUNT(*) FROM requests")
    assert cur.fetchone()[0] >= 1

    cur = store.conn.execute("SELECT method, url FROM requests LIMIT 1")
    method, url = cur.fetchone()
    assert method == "GET"
    assert "/" in url
