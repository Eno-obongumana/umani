import httpx
from time import perf_counter
from .models import Request, Response


class Requester:
    def __init__(self, scope, datastore=None, timeout=10.0, rate_limit=0.0,
                 user_agent="UMANI/0.1 (+authorized-testing-only)"):
        self.scope = scope
        self.db = datastore
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.client = httpx.Client(
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": user_agent},
        )

    def send(self, method, url, headers=None, body=None, scan_id=0):
        self.scope.check(url)
        start = perf_counter()
        resp = self.client.request(method, url, headers=headers, content=body)
        elapsed = int((perf_counter() - start) * 1000)

        req = Request(id=None, scan_id=scan_id, method=method, url=url,
                      headers=dict(resp.request.headers), body=body)
        res = Response(id=None, request_id=0, status=resp.status_code,
                       headers=dict(resp.headers), body=resp.content,
                       elapsed_ms=elapsed)

        if self.db:
            req_id = self.db.save_request(req)
            res.request_id = req_id
            res_id = self.db.save_response(res)
            req.id = req_id
            res.id = res_id

        return req, res

    def get(self, url, **kw):
        return self.send("GET", url, **kw)

    def post(self, url, body=None, **kw):
        return self.send("POST", url, body=body, **kw)
