"""Identity & normalization — the single most important correctness rule.

Nodes are keyed by a normalized canonical value (§12). Every importer builds
ids through here so that re-importing the same host/url/ip upserts one node
instead of creating duplicates. Normalization rules live in exactly one place.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from .model import NodeType

# Short, stable id prefixes per node type.
_PREFIX: dict[NodeType, str] = {
    NodeType.program: "prog",
    NodeType.domain: "dom",
    NodeType.subdomain: "sub",
    NodeType.ip: "ip",
    NodeType.asn: "asn",
    NodeType.service: "svc",
    NodeType.endpoint: "ep",
    NodeType.parameter: "param",
    NodeType.technology: "tech",
    NodeType.certificate: "cert",
    NodeType.finding: "finding",
    NodeType.functionality: "func",
}


def normalize_host(host: str) -> str:
    """Lowercase, strip whitespace and a single trailing dot. IDNA-encode."""
    h = host.strip().lower().rstrip(".")
    try:
        h = h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        pass
    return h


def normalize_ip(addr: str) -> str:
    """Canonical compressed form; raises ValueError on garbage input."""
    return str(ipaddress.ip_address(addr.strip()))


def normalize_url(url: str) -> str:
    """Canonical host+path key for an endpoint.

    Drops scheme and default ports, lowercases host, strips a trailing slash
    (except root), and discards query/fragment — query *values* become
    ``parameter`` nodes, not part of the endpoint identity.
    """
    if "://" not in url:
        url = "//" + url
    parts = urlsplit(url)
    host = normalize_host(parts.hostname or "")
    port = parts.port
    netloc = host
    if port and not ((parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return urlunsplit(("", netloc, path, "", "")).lstrip("/") or netloc


def normalize_value(node_type: NodeType, value: str) -> str:
    if node_type in (NodeType.domain, NodeType.subdomain, NodeType.certificate):
        return normalize_host(value)
    if node_type == NodeType.ip:
        return normalize_ip(value)
    if node_type == NodeType.endpoint:
        return normalize_url(value)
    if node_type == NodeType.technology:
        return value.strip().lower()
    return value.strip()


def make_id(node_type: NodeType, value: str) -> str:
    """Natural key = ``<prefix>:<normalized value>``."""
    return f"{_PREFIX[node_type]}:{normalize_value(node_type, value)}"


def host_of_url(url: str) -> str:
    """Extract the normalized host from a URL (to link endpoint → subdomain)."""
    if "://" not in url:
        url = "//" + url
    return normalize_host(urlsplit(url).hostname or "")


# A small set of common multi-label public suffixes so that
# ``api.example.co.uk`` → apex ``example.co.uk`` rather than ``co.uk``. This is
# a pragmatic shortlist, not the full Public Suffix List; swap in `publicsuffix2`
# if precise registrable-domain handling becomes necessary.
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "net.au",
    "org.au", "co.nz", "com.br", "com.cn", "co.in", "co.za",
}


def registrable_domain(host: str) -> str:
    """Best-effort apex domain (``api.example.com`` → ``example.com``)."""
    host = normalize_host(host)
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
