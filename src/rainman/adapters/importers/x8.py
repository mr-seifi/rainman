"""x8 (-O json) importer → discovered parameter nodes + has_param edges.

Carries each param's ``location`` (query/body/header) and the ``reflected``
flag, which is exactly the signal x8 exists to produce.
"""

from __future__ import annotations

from typing import Iterator

from ...domain.model import EdgeOp, EdgeType, NodeOp, NodeType
from .base import emit_url, param_key


class X8Importer:
    name = "x8"

    def parse(self, raw: str) -> Iterator[NodeOp | EdgeOp]:
        from .base import iter_json_lines

        for rec in iter_json_lines(raw):
            url = rec.get("url")
            if not url:
                continue
            # endpoint (+ host), without re-deriving params from the URL — x8
            # reports the discovered params explicitly below.
            yield from emit_url(
                url, self.name, method=rec.get("method"), with_params=False
            )
            params = rec.get("found_params") or rec.get("parameters") or []
            for p in params:
                if isinstance(p, str):
                    name, location, reflected = p, "query", None
                else:
                    name = p.get("name")
                    location = p.get("location") or p.get("place") or "query"
                    reflected = p.get("reflected")
                if not name:
                    continue
                pkey = param_key(url, name)
                props = {"name": name, "location": location}
                if reflected is not None:
                    props["reflected"] = reflected
                yield NodeOp(NodeType.parameter, pkey, source=self.name, props=props)
                yield EdgeOp(
                    EdgeType.has_param,
                    NodeType.endpoint, url,
                    NodeType.parameter, pkey,
                    source=self.name,
                )
