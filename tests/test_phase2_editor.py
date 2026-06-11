from fastapi.testclient import TestClient

from rainman.adapters.api import create_app


def seeded_client():
    c = TestClient(create_app(":memory:"))
    httpx = (
        '{"url":"https://api.example.com/v2/users","status_code":200,"ip":"203.0.113.10"}\n'
        '{"url":"https://api.example.com/login","status_code":401,"ip":"203.0.113.10"}'
    )
    c.post("/import/httpx", content=httpx, headers={"content-type": "text/plain"})
    return c


EP_USERS = "ep:api.example.com/v2/users"
EP_LOGIN = "ep:api.example.com/login"
HOST = "sub:api.example.com"


def test_create_functionality_from_members():
    c = seeded_client()
    r = c.post("/functionality", json={
        "name": "user management", "description": "user CRUD",
        "members": [EP_USERS, EP_LOGIN],
    })
    assert r.status_code == 200
    func_id = r.json()["node"]["id"]
    # both endpoints are part_of the functionality
    nb = c.get("/node", params={"id": func_id}).json()
    assert {n["id"] for n in nb["neighbors"]} >= {EP_USERS, EP_LOGIN}
    assert all(e["type"] == "part_of" for e in nb["edges"])


def test_add_finding_links_affected_nodes():
    c = seeded_client()
    r = c.post("/finding", json={
        "title": "IDOR on /v2/users", "kind": "suspected", "severity": "high",
        "confidence": 0.7, "affects": [EP_USERS, HOST],
    })
    fid = r.json()["node"]["id"]
    node = c.get("/node", params={"id": fid}).json()
    assert node["node"]["props"]["severity"] == "high"
    assert node["node"]["props"]["kind"] == "suspected"
    assert {n["id"] for n in node["neighbors"]} == {EP_USERS, HOST}
    assert all(e["type"] == "affects" for e in node["edges"])


def test_intuition_promotes_to_confirmed():
    c = seeded_client()
    fid = c.post("/finding", json={"title": "vhost confusion", "kind": "intuition",
                                   "confidence": 0.4, "affects": [HOST]}).json()["node"]["id"]
    # promote: untriaged -> in_scope -> testing -> confirmed is multi-step; flagged path
    c.patch("/node", params={"id": fid}, json={"status": "in_scope"})
    c.patch("/node", params={"id": fid}, json={"status": "flagged"})
    r = c.patch("/node", params={"id": fid}, json={"status": "confirmed"})
    assert r.status_code == 200


def test_manual_edge_by_id_and_delete():
    c = seeded_client()
    func = c.post("/functionality", json={"name": "auth"}).json()["node"]["id"]
    r = c.post("/edge", json={"type": "part_of", "from_id": EP_LOGIN, "to_id": func})
    assert r.status_code == 200
    edge_id = r.json()["edge"]["id"]
    assert c.delete("/edge", params={"id": edge_id}).status_code == 200
    assert c.delete("/edge", params={"id": edge_id}).status_code == 404


def test_edge_requires_existing_nodes():
    c = seeded_client()
    r = c.post("/edge", json={"type": "affects", "from_id": "finding:nope", "to_id": HOST})
    assert r.status_code == 404


def test_bulk_status_skips_illegal_and_missing():
    c = seeded_client()
    r = c.post("/bulk/status", json={
        "ids": [EP_USERS, EP_LOGIN, "sub:does.not.exist"],
        "status": "in_scope", "add_tags": ["triaged"],
    })
    body = r.json()
    assert set(body["updated"]) == {EP_USERS, EP_LOGIN}
    assert body["skipped"] == ["sub:does.not.exist"]
    # tag applied
    assert "triaged" in c.get("/node", params={"id": EP_USERS}).json()["node"]["tags"]


def test_set_tags_replaces_and_can_remove():
    c = seeded_client()
    c.patch("/node", params={"id": EP_USERS}, json={"add_tags": ["a", "b", "c"]})
    assert set(c.get("/node", params={"id": EP_USERS}).json()["node"]["tags"]) == {"a", "b", "c"}
    # set_tags is authoritative — removes b and c
    c.patch("/node", params={"id": EP_USERS}, json={"set_tags": ["a"]})
    assert c.get("/node", params={"id": EP_USERS}).json()["node"]["tags"] == ["a"]
    # empty set_tags clears all
    c.patch("/node", params={"id": EP_USERS}, json={"set_tags": []})
    assert c.get("/node", params={"id": EP_USERS}).json()["node"]["tags"] == []


def test_bulk_tag_only_without_status():
    c = seeded_client()
    r = c.post("/bulk/status", json={"ids": [EP_USERS, EP_LOGIN], "add_tags": ["review"]})
    assert set(r.json()["updated"]) == {EP_USERS, EP_LOGIN}
    for ep in (EP_USERS, EP_LOGIN):
        assert "review" in c.get("/node", params={"id": ep}).json()["node"]["tags"]
    # status unchanged
    assert c.get("/node", params={"id": EP_USERS}).json()["node"]["status"] == "untriaged"


def test_delete_node_removes_incident_edges():
    c = seeded_client()
    c.post("/functionality", json={"name": "auth", "members": [EP_LOGIN]})
    c.delete("/node", params={"id": EP_LOGIN})
    # host no longer sees the deleted endpoint
    nb = c.get("/node", params={"id": HOST}).json()
    assert EP_LOGIN not in {n["id"] for n in nb["neighbors"]}
