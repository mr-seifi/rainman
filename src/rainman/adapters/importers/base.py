"""Shared helpers for tool output: JSONL parsing, plain line lists, and the
common URL → endpoint(+params) emit path reused by every URL-shaped tool
(katana, gau, waybackurls, ffuf, kiteRunner, …)."""

from __future__ import annotations

import json
from typing import Iterator, Optional
from urllib.parse import parse_qsl, urlsplit

from ...domain.identity import host_of_url, normalize_url
from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType


def iter_json_lines(raw: str) -> Iterator[dict]:
    """Yield objects from JSONL, a concatenated stream, or a top-level array.

    Most of the recon stack emits newline-delimited JSON (``-json``); some emit
    a single array. This tolerates both, plus blank lines.
    """
    raw = raw.strip()
    if not raw:
        return
    if raw[0] == "[":
        for obj in json.loads(raw):
            yield obj
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def iter_lines(raw: str) -> Iterator[str]:
    """Yield non-blank, comment-free lines from a plain text list."""
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def param_key(url: str, name: str) -> str:
    """Canonical parameter value: scoped to its endpoint so the same name on
    two endpoints stays two distinct nodes (``…/users#id`` vs ``…/posts#id``)."""
    return f"{normalize_url(url)}#{name}"


def emit_url(
    url: str,
    source: str,
    *,
    method: Optional[str] = None,
    status: Optional[int] = None,
    length: Optional[int] = None,
    tags: Optional[list[str]] = None,
    extra_props: Optional[dict] = None,
    with_params: bool = True,
) -> Iterator[NodeOp | EdgeOp]:
    """The shared host → endpoint (→ params) emit used by every URL-shaped
    importer. Yields the subdomain, the endpoint with its props, the
    has_endpoint edge, and one parameter node + has_param edge per query key.
    """
    host = host_of_url(url)
    if not host:
        return
    tags = tags or []

    yield NodeOp(NodeType.subdomain, host, source=source)

    ep_props = {
        "method": (method or "GET").upper(),
        "status_code": status,
        "content_length": length,
    }
    if extra_props:
        ep_props.update(extra_props)
    ep_props = {k: v for k, v in ep_props.items() if v is not None}
    yield NodeOp(NodeType.endpoint, url, source=source, tags=tags, props=ep_props)
    yield EdgeOp(
        EdgeType.has_endpoint,
        NodeType.subdomain, host,
        NodeType.endpoint, url,
        source=source,
    )

    if with_params:
        query = urlsplit(url if "://" in url else "//" + url).query
        for name, example in parse_qsl(query, keep_blank_values=True):
            pkey = param_key(url, name)
            pprops = {"name": name, "location": "query"}
            if example:
                pprops["example"] = example
            yield NodeOp(NodeType.parameter, pkey, source=source, props=pprops)
            yield EdgeOp(
                EdgeType.has_param,
                NodeType.endpoint, url,
                NodeType.parameter, pkey,
                source=source,
            )
