import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import httpx
from .models import Request, Response


class _ProxyHandler(BaseHTTPRequestHandler):
    datastore = None
    scope = None
    client = None

    def log_message(self, *args):
        pass  # silence default output

    def _forward(self, method: str):
        url = self.path
        # only absolute URLs are proxied (GET http://... HTTP/1.1)
        if not url.startswith(("http://", "https://")):
            self.send_error(400, "only absolute-form requests supported")
            return

        # read body if any
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        # strip hop-by-hop headers
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "proxy-connection",
                                        "connection", "content-length")}

        try:
            resp = self.client.request(method, url, headers=headers,
                                        content=body)
        except Exception as e:
            self.send_error(502, f"upstream error: {e}")
            return

        if self.datastore is not None:
            try:
                req = Request(id=None, scan_id=0, method=method, url=url,
                              headers=headers, body=body)
                req_id = self.datastore.save_request(req)
                res = Response(id=None, request_id=req_id,
                               status=resp.status_code,
                               headers=dict(resp.headers),
                               body=resp.content,
                               elapsed_ms=0)
                self.datastore.save_response(res)
            except Exception as e:
                import traceback
                print(f"[proxy] logging failed: {e}")
                traceback.print_exc()
        # --- relay to browser ---
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            if k.lower() in ("content-length", "transfer-encoding",
                             "connection"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp.content)))
        self.end_headers()
        self.wfile.write(resp.content)

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_DELETE(self):
        self._forward("DELETE")

    def do_HEAD(self):
        self._forward("HEAD")

    def do_OPTIONS(self):
        self._forward("OPTIONS")

    def do_PATCH(self):
        self._forward("PATCH")


class Proxy:
    def __init__(self, datastore, scope, host="127.0.0.1", port=8080):
        self.host = host
        self.port = port
        self.datastore = datastore
        _ProxyHandler.datastore = datastore
        _ProxyHandler.scope = scope
        _ProxyHandler.client = httpx.Client(timeout=20.0, follow_redirects=False)
        self._server = ThreadingHTTPServer((host, port), _ProxyHandler)
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
