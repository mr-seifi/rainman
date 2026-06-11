"""nmap (-oX XML) importer → service nodes + runs_service edges off the IP.

Service identity is ``ip:port/proto`` so re-scanning the same host upserts the
same service node and just enriches product/version/state.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Iterator

from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType


def service_value(ip: str, port: str, proto: str) -> str:
    return f"{ip}:{port}/{proto}"


class NmapImporter:
    name = "nmap"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        root = ET.fromstring(raw)
        for host in root.findall("host"):
            ip = None
            for addr in host.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr")
                    break
            if not ip:
                continue
            yield NodeOp(NodeType.ip, ip, source=self.name)

            # Link any resolved hostnames back to the IP.
            for hn in host.findall("./hostnames/hostname"):
                name = hn.get("name")
                if name:
                    yield NodeOp(NodeType.subdomain, name, source=self.name)
                    yield EdgeOp(
                        EdgeType.resolves_to,
                        NodeType.subdomain, name,
                        NodeType.ip, ip,
                        source=self.name,
                    )

            for port in host.findall("./ports/port"):
                proto = port.get("protocol", "tcp")
                portid = port.get("portid")
                if not portid:
                    continue
                state_el = port.find("state")
                svc_el = port.find("service")
                props = {
                    "port": int(portid),
                    "protocol": proto,
                    "state": state_el.get("state") if state_el is not None else None,
                }
                if svc_el is not None:
                    for k in ("name", "product", "version", "extrainfo"):
                        if svc_el.get(k):
                            props[k] = svc_el.get(k)
                props = {k: v for k, v in props.items() if v is not None}
                value = service_value(ip, portid, proto)
                yield NodeOp(NodeType.service, value, source=self.name, props=props)
                yield EdgeOp(
                    EdgeType.runs_service,
                    NodeType.ip, ip,
                    NodeType.service, value,
                    source=self.name,
                )
