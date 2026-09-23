import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from time import time


class _Handler(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Handler.hits.append({
            "path": self.path,
            "client": self.client_address[0],
            "time": time(),
        })
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"umani-canary")

    def log_message(self, *args):
        pass  # silence


class Canary:
    """A tiny HTTP listener that records any inbound request.
    Used to detect SSRF: if the target server fetches the canary URL,
    we see the connection here."""

    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        _Handler.hits = []
        self._server = HTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/umani-canary"

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()

    def hits(self) -> list[dict]:
        return list(_Handler.hits)

    def clear(self):
        _Handler.hits = []
