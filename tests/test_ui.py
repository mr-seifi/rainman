from fastapi.testclient import TestClient

from rainman.adapters.api import create_app

HTTPX = '{"url":"https://api.example.com/v2/users","status_code":200,"tech":["nginx"],"ip":"203.0.113.10"}'
SHUFFLE = "api.example.com\nadmin.example.com\n"


def test_index_served():
    c = TestClient(create_app(":memory:"))
    r = c.get("/")
    assert r.status_code == 200
    assert "rain" in r.text and "cytoscape" in r.text.lower()


def test_roots_prefers_domains():
    c = TestClient(create_app(":memory:"))
    c.post("/import/shuffledns", content=SHUFFLE, headers={"content-type": "text/plain"})
    roots = c.get("/roots").json()["nodes"]
    assert {n["type"] for n in roots} == {"domain"}
    assert any(n["value"] == "example.com" for n in roots)


def test_roots_falls_back_to_subdomains():
    c = TestClient(create_app(":memory:"))
    c.post("/import/httpx", content=HTTPX, headers={"content-type": "text/plain"})
    roots = c.get("/roots").json()["nodes"]
    assert roots and all(n["type"] == "subdomain" for n in roots)
