"""shuffledns importer → subdomain nodes + subdomain_of edges.

Accepts a plain resolved-FQDN list (``shuffledns -o``) or massdns lines
(``host A 1.2.3.4``); the latter also yields the ip + resolves_to edge.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.identity import registrable_domain
from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import iter_lines


class ShufflednsImporter:
    name = "shuffledns"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for line in iter_lines(raw):
            parts = line.split()
            host = parts[0].rstrip(".")
            yield from self._host(host)
            # massdns form: "<host> A <ip>" / "<host> AAAA <ip>"
            if len(parts) >= 3 and parts[1] in ("A", "AAAA"):
                ip = parts[2]
                yield NodeOp(NodeType.ip, ip, source=self.name)
                yield EdgeOp(
                    EdgeType.resolves_to,
                    NodeType.subdomain, host,
                    NodeType.ip, ip,
                    source=self.name,
                )

    def _host(self, host: str) -> Iterator[NodeOp | EdgeOp]:
        apex = registrable_domain(host)
        if host == apex:
            yield NodeOp(NodeType.domain, host, source=self.name)
            return
        yield NodeOp(NodeType.subdomain, host, source=self.name)
        yield NodeOp(NodeType.domain, apex, source=self.name)
        yield EdgeOp(
            EdgeType.subdomain_of,
            NodeType.subdomain, host,
            NodeType.domain, apex,
            source=self.name,
        )
