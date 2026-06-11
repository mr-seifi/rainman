"""subfinder (-oJ / -json) importer → subdomain nodes + subdomain_of edges.

Each record is ``{"host","input","source"}`` where ``input`` is the apex domain
that was enumerated (so no registrable-domain guessing is needed) and
``source`` is subfinder's discovery source (rapiddns, crtsh, …), kept on the
node as provenance.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.identity import normalize_host
from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import iter_json_lines


class SubfinderImporter:
    name = "subfinder"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            host = rec.get("host")
            if not host:
                continue
            host = normalize_host(host)
            apex = normalize_host(rec.get("input") or "")
            via = rec.get("source")
            props = {"discovered_via": via} if via else {}

            if not apex or host == apex:
                yield NodeOp(NodeType.domain, host, source=self.name, props=props)
                continue

            yield NodeOp(NodeType.subdomain, host, source=self.name, props=props)
            yield NodeOp(NodeType.domain, apex, source=self.name)
            yield EdgeOp(
                EdgeType.subdomain_of,
                NodeType.subdomain, host,
                NodeType.domain, apex,
                source=self.name,
            )
