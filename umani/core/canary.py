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
    Used to detect SSRF/XXE: if the target server fetches the canary URL,
    we see the connection here.

    Pass port=0 to let the OS assign a free port — recommended when
    multiple Canaries run in the same process.
    """

    def __init__(self, host="127.0.0.1", port=0):
        self.host = host
        _Handler.hits = []
        # pass 0 to let the OS pick a free port
        self._server = HTTPServer((host, port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/umani-canary"

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()

    def hits(self) -> list[dict]:
        return list(_Handler.hits)

    def clear(self):
        _Handler.hits = []
