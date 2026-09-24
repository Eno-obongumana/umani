import threading
import time
import httpx
from umani.core.scope import Scope
from umani.core.datastore import Datastore
from umani.core.proxy import Proxy
from umani.core.intercept import QUEUE


def test_intercept_pauses_and_forwards(simple_flask, tmp_path):
    db_path = tmp_path / "intercept.db"
    store = Datastore(str(db_path))
    scope = Scope()

    proxy = Proxy(store, scope, host="127.0.0.1", port=0, intercept=True)
    proxy.start()
    port = proxy._server.server_address[1]

    result = {}

    def _client():
        try:
            client = httpx.Client(proxy=f"http://127.0.0.1:{port}",
                                   timeout=10.0)
            r = client.get(f"{simple_flask}/")
            result["status"] = r.status_code
        except Exception as e:
            result["error"] = str(e)

    t = threading.Thread(target=_client, daemon=True)
    t.start()

    # wait for the request to land in the queue
    item = None
    for _ in range(50):
        time.sleep(0.1)
        pending = QUEUE.list_pending()
        if pending:
            item = pending[0]
            break
    assert item is not None, "request never reached the intercept queue"

    # forward it untouched
    ok = QUEUE.forward(item.id)
    assert ok

    t.join(timeout=5)
    proxy.stop()

    assert result.get("status") == 200, result


def test_intercept_can_drop(simple_flask, tmp_path):
    db_path = tmp_path / "intercept-drop.db"
    store = Datastore(str(db_path))
    scope = Scope()

    proxy = Proxy(store, scope, host="127.0.0.1", port=0, intercept=True)
    proxy.start()
    port = proxy._server.server_address[1]

    result = {}

    def _client():
        try:
            client = httpx.Client(proxy=f"http://127.0.0.1:{port}",
                                   timeout=10.0)
            r = client.get(f"{simple_flask}/")
            result["status"] = r.status_code
        except Exception as e:
            result["error"] = str(e)

    t = threading.Thread(target=_client, daemon=True)
    t.start()

    item = None
    for _ in range(50):
        time.sleep(0.1)
        pending = QUEUE.list_pending()
        if pending:
            item = pending[0]
            break
    assert item is not None

    ok = QUEUE.drop(item.id)
    assert ok

    t.join(timeout=5)
    proxy.stop()

    # client should NOT get a 200 — the request was dropped
    assert result.get("status") != 200
