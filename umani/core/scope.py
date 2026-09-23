from urllib.parse import urlparse
import ipaddress
import yaml
from pathlib import Path


DEFAULT_SCOPE = {
    "allow": ["127.0.0.1", "localhost", "::1"],
    "deny": [],
}


class ScopeError(Exception):
    pass


class Scope:
    def __init__(self, scope_file=None):
        if scope_file and Path(scope_file).exists():
            with open(scope_file) as f:
                data = yaml.safe_load(f)
        else:
            data = DEFAULT_SCOPE
        self.allow = data.get("allow", [])
        self.deny = data.get("deny", [])

    def _matches(self, host, pattern):
        if pattern == host:
            return True
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            try:
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        except ValueError:
            pass
        if pattern.startswith("*."):
            return host.endswith(pattern[1:])
        return False

    def is_allowed(self, url):
        host = urlparse(url).hostname
        if not host:
            return False
        if any(self._matches(host, d) for d in self.deny):
            return False
        return any(self._matches(host, a) for a in self.allow)

    def check(self, url):
        if not self.is_allowed(url):
            raise ScopeError(
                f"Target {url} is out of scope. "
                f"Edit scope.yaml to allow it. "
                f"Only scan systems you own or have written permission to test."
            )
