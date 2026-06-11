"""httpx (-json) importer.

Maps each probe record to the live host + endpoint and enriches it with
status/title/tech/ip/cert, per PROPOSAL.md §7.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.identity import host_of_url
from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import iter_json_lines


class HttpxImporter:
    name = "httpx"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        for rec in iter_json_lines(raw):
            yield from self._one(rec)

    def _one(self, rec: dict) -> Iterator[NodeOp | EdgeOp]:
        url = rec.get("url") or rec.get("input")
        if not url:
            return
        host = host_of_url(url)
        if not host:
            return

        # Host (subdomain) node — enriched but not re-statused.
        host_props = {}
        if rec.get("cdn") or rec.get("cdn_name"):
            host_props["cdn"] = rec.get("cdn_name") or True
        yield NodeOp(NodeType.subdomain, host, source=self.name, props=host_props)

        # Endpoint node.
        ep_props = {
            "method": (rec.get("method") or "GET").upper(),
            "status_code": rec.get("status_code") or rec.get("status-code"),
            "content_length": rec.get("content_length") or rec.get("content-length"),
            "content_type": rec.get("content_type") or rec.get("content-type"),
            "title": rec.get("title"),
            "webserver": rec.get("webserver"),
            "scheme": rec.get("scheme") or (url.split("://", 1)[0] if "://" in url else None),
        }
        ep_props = {k: v for k, v in ep_props.items() if v is not None}
        yield NodeOp(NodeType.endpoint, url, source=self.name, props=ep_props)
        yield EdgeOp(
            EdgeType.has_endpoint,
            NodeType.subdomain, host,
            NodeType.endpoint, url,
            source=self.name,
        )

        # Technologies.
        for tech in rec.get("tech") or rec.get("technologies") or []:
            yield NodeOp(NodeType.technology, tech, source=self.name)
            yield EdgeOp(
                EdgeType.uses_tech,
                NodeType.subdomain, host,
                NodeType.technology, tech,
                source=self.name,
            )

        # Resolved IP(s).
        ips = []
        if rec.get("ip"):
            ips.append(rec["ip"])
        ips.extend(rec.get("a") or [])
        for ip in dict.fromkeys(ips):
            yield NodeOp(NodeType.ip, ip, source=self.name)
            yield EdgeOp(
                EdgeType.resolves_to,
                NodeType.subdomain, host,
                NodeType.ip, ip,
                source=self.name,
            )

        # TLS certificate — the SAN list is what links hosts (shared infra).
        tls = rec.get("tls") or {}
        sans = tls.get("subject_an") or tls.get("subject_alt_names") or []
        cert_key = tls.get("fingerprint_sha256") or tls.get("subject_cn") or (sans[0] if sans else None)
        if cert_key:
            cert_props = {"sans": sans, "subject_cn": tls.get("subject_cn"), "issuer": tls.get("issuer_cn")}
            cert_props = {k: v for k, v in cert_props.items() if v}
            yield NodeOp(NodeType.certificate, cert_key, source=self.name, props=cert_props)
            yield EdgeOp(
                EdgeType.shares_cert,
                NodeType.subdomain, host,
                NodeType.certificate, cert_key,
                source=self.name,
            )
            for san in sans:
                if san.startswith("*.") or san == host:
                    continue
                yield NodeOp(NodeType.subdomain, san, source=self.name)
                yield EdgeOp(
                    EdgeType.shares_cert,
                    NodeType.subdomain, san,
                    NodeType.certificate, cert_key,
                    source=self.name,
                )
