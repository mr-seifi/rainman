"""Domain core — canonical graph model, identity, ports, ingest.

This package is intentionally dependency-free: no FastAPI, no DB driver, no
renderer. It depends only on the standard library and on its own interfaces
(ports). Concrete stores, importers, and renderers are adapters that live
outside this package and implement these ports.
"""
