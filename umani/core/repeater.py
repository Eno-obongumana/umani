import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from .requester import Requester


class Repeater:
    def __init__(self, datastore, scope):
        self.db = datastore
        self.scope = scope
        self.http = Requester(scope, datastore)

    def _apply_param(self, url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

    def replay(self, finding_id: int,
               override_url=None,
               override_method=None,
               override_body=None,
               add_headers=None,
               set_params=None):
        finding = self.db.get_finding(finding_id)
        if not finding:
            raise ValueError(f"finding {finding_id} not found")

        req_id = finding["request_id"]
        original_req = self.db.get_request(req_id) if req_id else None
        original_res = self.db.get_response_for_request(req_id) if req_id else None

        url = override_url or (original_req["url"] if original_req
                               else finding["url"])
        method = override_method or (original_req["method"] if original_req
                                     else "GET")
        body = override_body if override_body is not None else (
            original_req["body"] if original_req else None)

        headers = {}
        if original_req and original_req["headers"]:
            try:
                headers = json.loads(original_req["headers"])
            except Exception:
                headers = {}
        if add_headers:
            headers.update(add_headers)

        if set_params:
            for k, v in set_params.items():
                url = self._apply_param(url, k, v)

        self.scope.check(url)
        new_req, new_res = self.http.send(method, url, headers=headers,
                                           body=body)

        return {
            "finding": finding,
            "original_request": original_req,
            "original_response": original_res,
            "new_request": {"method": method, "url": url,
                            "headers": headers, "body": body},
            "new_response": {
                "status": new_res.status,
                "length": len(new_res.body),
                "elapsed_ms": new_res.elapsed_ms,
                "body_preview": new_res.body[:512].decode("utf-8",
                                                          errors="ignore"),
            },
        }
