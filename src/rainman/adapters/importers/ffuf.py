"""ffuf (-of json) importer.

ffuf is mode-agnostic in its output, so we read the run's ``config`` to tell
content discovery from vhost-mode from param-fuzz, then map each result:
content → endpoint, vhost → subdomain, param → parameter (PROPOSAL.md §7).
"""

from __future__ import annotations

import json
from typing import Iterator

from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import emit_url, param_key


class FfufImporter:
    name = "ffuf"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        data = json.loads(raw)
        if isinstance(data, list):
            data = {"results": data, "config": {}}
        config = data.get("config") or {}
        mode = self._mode(config)
        for r in data.get("results") or []:
            yield from self._result(r, mode)

    @staticmethod
    def _mode(config: dict) -> str:
        headers = config.get("headers") or {}
        for k, v in headers.items():
            if k.lower() == "host" and "FUZZ" in str(v):
                return "vhost"
        url = config.get("url") or ""
        if "?" in url and "FUZZ" in url.split("?", 1)[1]:
            return "param"
        return "content"

    def _result(self, r: dict, mode: str) -> Iterator[NodeOp | EdgeOp]:
        url = r.get("url")
        status = r.get("status")
        length = r.get("length")
        fuzz = r.get("input") or {}

        if mode == "vhost":
            host = r.get("host") or next(iter(fuzz.values()), None)
            if host:
                yield NodeOp(NodeType.subdomain, host, source=self.name, tags=["vhost"])
            return

        if mode == "param" and url:
            # the endpoint being fuzzed must exist for the params to hang off
            yield from emit_url(url, self.name, status=status, length=length, with_params=False)
            for val in fuzz.values():
                pkey = param_key(url, str(val))
                yield NodeOp(
                    NodeType.parameter, pkey, source=self.name,
                    props={"name": str(val), "location": "query"},
                )
                yield EdgeOp(
                    EdgeType.has_param,
                    NodeType.endpoint, url,
                    NodeType.parameter, pkey,
                    source=self.name,
                )
            return

        if url:
            yield from emit_url(
                url, self.name, status=status, length=length,
                tags=["content-discovery"],
            )
