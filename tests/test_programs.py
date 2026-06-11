from fastapi.testclient import TestClient

from rainman.adapters.api import create_app

HTTPX = '{"url":"https://api.acme.com/v1","status_code":200,"ip":"10.0.0.1"}'


def test_programs_are_isolated():
    c = TestClient(create_app(":memory:"))
    c.post("/import/httpx?program=acme", content=HTTPX, headers={"content-type": "text/plain"})
    c.post("/import/shuffledns?program=globex",
           content="api.globex.com\nadmin.globex.com\n", headers={"content-type": "text/plain"})

    progs = {p["program"]: p["nodes"] for p in c.get("/programs").json()["programs"]}
    assert set(progs) == {"acme", "globex"}

    # roots are scoped per program
    acme_roots = {n["value"] for n in c.get("/roots", params={"program": "acme"}).json()["nodes"]}
    globex_roots = {n["value"] for n in c.get("/roots", params={"program": "globex"}).json()["nodes"]}
    assert "api.acme.com" in acme_roots
    assert "globex.com" in globex_roots
    assert acme_roots.isdisjoint(globex_roots)

    # digest is scoped
    assert c.get("/digest", params={"program": "acme"}).json()["total_nodes"] < \
           c.get("/digest").json()["total_nodes"]


def test_same_host_in_two_programs_stays_separate():
    c = TestClient(create_app(":memory:"))
    line = "shared.example.com\n"
    c.post("/import/shuffledns?program=a", content=line, headers={"content-type": "text/plain"})
    c.post("/import/shuffledns?program=b", content=line, headers={"content-type": "text/plain"})
    # both programs are non-default, so each host id is namespaced and distinct
    assert c.get("/node", params={"id": "a::sub:shared.example.com"}).status_code == 200
    assert c.get("/node", params={"id": "b::sub:shared.example.com"}).status_code == 200


def test_default_program_ids_unprefixed():
    c = TestClient(create_app(":memory:"))
    c.post("/import/httpx", content=HTTPX, headers={"content-type": "text/plain"})  # default
    assert c.get("/node", params={"id": "sub:api.acme.com"}).status_code == 200
