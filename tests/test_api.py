from fastapi.testclient import TestClient

from rainman.adapters.api import create_app


def client():
    return TestClient(create_app(":memory:"))


HTTPX = '{"url":"https://api.example.com/v2/users","status_code":200,"tech":["nginx"],"ip":"203.0.113.10"}'


def test_import_and_node_detail():
    c = client()
    r = c.post("/import/httpx", content=HTTPX, headers={"content-type": "text/plain"})
    assert r.status_code == 200
    assert r.json()["nodes"] > 0

    d = c.get("/digest").json()
    assert d["total_nodes"] > 0

    r = c.get("/node", params={"id": "sub:api.example.com"})
    assert r.status_code == 200
    body = r.json()
    assert body["node"]["value"] == "api.example.com"
    assert any(n["type"] == "endpoint" for n in body["neighbors"])


def test_patch_status_rejects_illegal_transition():
    c = client()
    c.post("/import/httpx", content=HTTPX, headers={"content-type": "text/plain"})
    r = c.patch("/node", params={"id": "sub:api.example.com"}, json={"status": "confirmed"})
    assert r.status_code == 409
    r = c.patch("/node", params={"id": "sub:api.example.com"}, json={"status": "in_scope"})
    assert r.status_code == 200


def test_manual_ingest_ops():
    c = client()
    r = c.post("/ingest", json={
        "nodes": [{"type": "functionality", "value": "auth flow", "source": "manual"}],
        "edges": [],
    })
    assert r.json()["nodes"] == 1
