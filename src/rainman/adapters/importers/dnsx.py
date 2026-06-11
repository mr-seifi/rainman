"""dnsx (-json) importer.

Maps DNS records to ip nodes and resolves_to / cname_to edges, with ptr
carried as a prop on the IP, per PROPOSAL.md §7.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import iter_json_lines


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


class DnsxImporter:
    name = "dnsx"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            yield from self._one(rec)

    def _one(self, rec: dict) -> Iterator[NodeOp | EdgeOp]:
        host = rec.get("host") or rec.get("name")
        if not host:
            return
        yield NodeOp(NodeType.subdomain, host, source=self.name)

        ptrs = _as_list(rec.get("ptr"))
        ip_props = {"ptr": ptrs[0]} if ptrs else {}

        for ip in _as_list(rec.get("a")) + _as_list(rec.get("aaaa")):
            yield NodeOp(NodeType.ip, ip, source=self.name, props=dict(ip_props))
            yield EdgeOp(
                EdgeType.resolves_to,
                NodeType.subdomain, host,
                NodeType.ip, ip,
                source=self.name,
            )

        for cname in _as_list(rec.get("cname")):
            yield NodeOp(NodeType.subdomain, cname, source=self.name)
            yield EdgeOp(
                EdgeType.cname_to,
                NodeType.subdomain, host,
                NodeType.subdomain, cname,
                source=self.name,
            )
