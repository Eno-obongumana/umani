"""
Intercept queue for the proxy.

When intercept is enabled, the proxy handler pauses before forwarding a
request, drops it in this queue, and blocks. A controller (CLI command)
inspects the queue and calls forward() or drop() to release the handler.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InterceptedRequest:
    id: int
    method: str
    url: str
    headers: dict
    body: Optional[bytes]
    created_at: float = field(default_factory=time.time)

    # these are set by the controller before releasing
    edited_method: Optional[str] = None
    edited_url: Optional[str] = None
    edited_headers: Optional[dict] = None
    edited_body: Optional[bytes] = None

    # synchronization
    done: threading.Event = field(default_factory=threading.Event)
    action: str = "pending"  # "pending" | "forward" | "drop"

    def final_method(self) -> str:
        return self.edited_method or self.method

    def final_url(self) -> str:
        return self.edited_url or self.url

    def final_headers(self) -> dict:
        return self.edited_headers if self.edited_headers is not None else self.headers

    def final_body(self) -> Optional[bytes]:
        return self.edited_body if self.edited_body is not None else self.body


class InterceptQueue:
    def __init__(self):
        self._lock = threading.Lock()
        self._next_id = 1
        self._items: dict[int, InterceptedRequest] = {}

    def submit(self, method: str, url: str, headers: dict,
               body: Optional[bytes],
               timeout: float = 60.0) -> InterceptedRequest:
        """Called from the proxy handler thread. Blocks until the
        controller releases the request or timeout expires."""
        with self._lock:
            item = InterceptedRequest(
                id=self._next_id, method=method, url=url,
                headers=dict(headers), body=body)
            self._items[item.id] = item
            self._next_id += 1

        # wait outside the lock so the controller can inspect
        item.done.wait(timeout=timeout)

        # if timeout expired and nothing happened, auto-forward
        if item.action == "pending":
            item.action = "forward"

        # remove from queue
        with self._lock:
            self._items.pop(item.id, None)

        return item

    def list_pending(self) -> list[InterceptedRequest]:
        with self._lock:
            return [i for i in self._items.values()
                    if i.action == "pending"]

    def get(self, item_id: int) -> Optional[InterceptedRequest]:
        with self._lock:
            return self._items.get(item_id)

    def forward(self, item_id: int,
                method: Optional[str] = None,
                url: Optional[str] = None,
                headers: Optional[dict] = None,
                body: Optional[bytes] = None) -> bool:
        with self._lock:
            item = self._items.get(item_id)
            if not item or item.action != "pending":
                return False
            item.edited_method = method
            item.edited_url = url
            item.edited_headers = headers
            item.edited_body = body
            item.action = "forward"
        item.done.set()
        return True

    def drop(self, item_id: int) -> bool:
        with self._lock:
            item = self._items.get(item_id)
            if not item or item.action != "pending":
                return False
            item.action = "drop"
        item.done.set()
        return True

    def clear(self):
        with self._lock:
            for item in list(self._items.values()):
                if item.action == "pending":
                    item.action = "drop"
                    item.done.set()
            self._items.clear()


# global singleton
QUEUE = InterceptQueue()
