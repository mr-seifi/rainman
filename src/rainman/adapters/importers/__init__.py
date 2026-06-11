"""Importer adapters + a name→importer registry (Strategy + Registry, §14).

``mapper import <tool>`` dispatches by name; adding a tool is dropping a new
module and registering it here, with zero changes elsewhere.
"""

from __future__ import annotations

from ...domain.ports import Importer
from .dnsx import DnsxImporter
from .ffuf import FfufImporter
from .gau import GauImporter
from .httpx import HttpxImporter
from .katana import KatanaImporter
from .kiterunner import KiteRunnerImporter
from .naabu import NaabuImporter
from .nmap import NmapImporter
from .shuffledns import ShufflednsImporter
from .subfinder import SubfinderImporter
from .waybackurls import WaybackurlsImporter
from .x8 import X8Importer

_REGISTRY: dict[str, Importer] = {}


def register(importer: Importer) -> None:
    _REGISTRY[importer.name] = importer


def get_importer(name: str) -> Importer:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"no importer registered for {name!r}; known: {sorted(_REGISTRY)}")


def available() -> list[str]:
    return sorted(_REGISTRY)


for _imp in (
    HttpxImporter(),
    DnsxImporter(),
    NmapImporter(),
    NaabuImporter(),
    ShufflednsImporter(),
    SubfinderImporter(),
    KatanaImporter(),
    GauImporter(),
    WaybackurlsImporter(),
    FfufImporter(),
    KiteRunnerImporter(),
    X8Importer(),
):
    register(_imp)
