import socket
from umani.core.scope import Scope
from umani.core.datastore import Datastore
from umani.core.proxy import Proxy


def test_proxy_handles_connect(simple_flask, tmp_path):
    """The proxy should accept a CONNECT and reply 200 Connection Established."""
    db_path = tmp_path / "proxy-https.db"
    store = Datastore(str(db_path))
    scope = Scope()

    proxy = Proxy(store, scope, host="127.0.0.1", port=0)
    proxy.start()
    port = proxy._server.server_address[1]

    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        request = (
            "CONNECT 127.0.0.1:5000 HTTP/1.1\r\n"
            "Host: 127.0.0.1:5000\r\n"
            "\r\n"
        )
        s.sendall(request.encode())
        resp = s.recv(1024)
        assert b"200" in resp, f"expected 200, got: {resp!r}"
        s.close()
    finally:
        proxy.stop()
