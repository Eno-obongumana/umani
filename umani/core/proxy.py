import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx
from .models import Request, Response
from .ca import CA


_CA = None


def get_ca() -> CA:
    global _CA
    if _CA is None:
        _CA = CA()
    return _CA


class _ProxyHandler(BaseHTTPRequestHandler):
    datastore = None
    scope = None
    client = None
    verbose = False

    def log_message(self, *args):
        if self.verbose:
            print("[proxy]", *args)

    def _forward(self, method: str):
        url = self.path
        if not url.startswith(("http://", "https://")):
            self.send_error(400, "only absolute-form requests supported")
            return

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "proxy-connection",
                                        "connection", "content-length")}
        try:
            resp = self.client.request(method, url, headers=headers,
                                        content=body)
        except Exception as e:
            self.send_error(502, f"upstream error: {e}")
            return

        self._log(method, url, headers, body, resp)

        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ("content-length", "transfer-encoding",
                             "connection"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp.content)))
        self.end_headers()
        self.wfile.write(resp.content)

    def do_GET(self): self._forward("GET")
    def do_POST(self): self._forward("POST")
    def do_PUT(self): self._forward("PUT")
    def do_DELETE(self): self._forward("DELETE")
    def do_HEAD(self): self._forward("HEAD")
    def do_OPTIONS(self): self._forward("OPTIONS")
    def do_PATCH(self): self._forward("PATCH")

    def do_CONNECT(self):
        host, _, port = self.path.partition(":")
        port = int(port or 443)

        self.send_response(200, "Connection Established")
        self.end_headers()

        try:
            cert_path, key_path = get_ca().leaf_for(host)
        except Exception as e:
            print(f"[proxy] cert gen failed for {host}: {e}")
            return

        ctx_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx_server.load_cert_chain(certfile=str(cert_path),
                                    keyfile=str(key_path))
        try:
            tls_client = ctx_server.wrap_socket(self.connection,
                                                 server_side=True)
        except ssl.SSLError as e:
            print(f"[proxy] TLS handshake with browser failed for {host}: {e}")
            return

        ctx_client = ssl.create_default_context()
        ctx_client.check_hostname = False
        ctx_client.verify_mode = ssl.CERT_NONE
        try:
            raw = socket.create_connection((host, port), timeout=10)
            tls_server = ctx_client.wrap_socket(raw, server_hostname=host)
        except Exception as e:
            print(f"[proxy] upstream TLS failed for {host}: {e}")
            tls_client.close()
            return

        self._bridge(tls_client, tls_server, host, port)

    def _bridge(self, a, b, host, port):
        a.settimeout(30)
        b.settimeout(30)

        def pump(src, dst, label):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    if label == "b→s":
                        self._log_https(host, port, data)
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try: dst.shutdown(socket.SHUT_WR)
                except Exception: pass

        t1 = threading.Thread(target=pump, args=(a, b, "b→s"), daemon=True)
        t2 = threading.Thread(target=pump, args=(b, a, "s→b"), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        try: a.close()
        except Exception: pass
        try: b.close()
        except Exception: pass

    def _log_https(self, host, port, data):
        try:
            head = data.split(b"\r\n", 1)[0].decode("utf-8", errors="ignore")
            if not head or " " not in head:
                return
            parts = head.split(" ", 2)
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]
            if method not in ("GET", "POST", "PUT", "DELETE", "HEAD",
                              "OPTIONS", "PATCH"):
                return
            url = f"https://{host}{path}"
            req = Request(id=None, scan_id=0, method=method, url=url,
                          headers={}, body=data[:4096])
            if self.datastore is not None:
                self.datastore.save_request(req)
        except Exception:
            pass

    def _log(self, method, url, headers, body, resp):
        if self.datastore is None:
            return
        try:
            req = Request(id=None, scan_id=0, method=method, url=url,
                          headers=headers, body=body)
            req_id = self.datastore.save_request(req)
            res = Response(id=None, request_id=req_id,
                           status=resp.status_code,
                           headers=dict(resp.headers),
                           body=resp.content, elapsed_ms=0)
            self.datastore.save_response(res)
        except Exception as e:
            print(f"[proxy] logging failed: {e}")


class Proxy:
    def __init__(self, datastore, scope, host="127.0.0.1", port=8080,
                 verbose=False):
        self.host = host
        self.port = port
        self.datastore = datastore
        _ProxyHandler.datastore = datastore
        _ProxyHandler.scope = scope
        _ProxyHandler.verbose = verbose
        _ProxyHandler.client = httpx.Client(
            timeout=20.0, follow_redirects=False, trust_env=False)
        self._server = ThreadingHTTPServer((host, port), _ProxyHandler)
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
