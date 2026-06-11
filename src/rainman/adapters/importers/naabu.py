"""naabu (-json) importer → fast service nodes (state=open) + runs_service.

Same service identity (``ip:port/proto``) as nmap, so a naabu sweep followed
by an nmap detail scan enriches one service node instead of duplicating it.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import iter_json_lines
from .nmap import service_value


class NaabuImporter:
    name = "naabu"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            ip = rec.get("ip")
            port = rec.get("port")
            if not ip or port is None:
                continue
            proto = (rec.get("protocol") or "tcp").lower()
            yield NodeOp(NodeType.ip, ip, source=self.name)

            host = rec.get("host")
            if host and host != ip:
                yield NodeOp(NodeType.subdomain, host, source=self.name)
                yield EdgeOp(
                    EdgeType.resolves_to,
                    NodeType.subdomain, host,
                    NodeType.ip, ip,
                    source=self.name,
                )

            value = service_value(ip, str(port), proto)
            yield NodeOp(
                NodeType.service, value, source=self.name,
                props={"port": int(port), "protocol": proto, "state": "open"},
            )
            yield EdgeOp(
                EdgeType.runs_service,
                NodeType.ip, ip,
                NodeType.service, value,
                source=self.name,
            )
