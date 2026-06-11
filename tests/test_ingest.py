import pytest

from rainman.adapters.importers import get_importer
from rainman.adapters.store import SqliteGraphRepository
from rainman.domain.identity import make_id
from rainman.domain.ingest import IngestService
from rainman.domain.model import NodeType, Status, can_transition


@pytest.fixture
def repo():
    r = SqliteGraphRepository(":memory:")
    yield r
    r.close()


HTTPX = (
    '{"url":"https://api.example.com/v2/users","status_code":200,'
    '"tech":["nginx","Node.js"],"ip":"203.0.113.10",'
    '"tls":{"subject_cn":"*.example.com","subject_an":["*.example.com","admin.example.com"]}}'
)

DNSX = '{"host":"api.example.com","a":["203.0.113.10"],"ptr":["host.cloud"]}'


def test_httpx_import_builds_graph(repo):
    svc = IngestService(repo)
    res = svc.ingest(get_importer("httpx").parse(HTTPX))
    assert res.nodes > 0 and res.edges > 0

    ep = repo.get_node(make_id(NodeType.endpoint, "https://api.example.com/v2/users"))
    assert ep is not None
    assert ep.props["status_code"] == 200

    # tech + ip + cert neighbors of the host
    host_id = make_id(NodeType.subdomain, "api.example.com")
    edges, neighbors = repo.neighbors(host_id)
    types = {n.type for n in neighbors}
    assert {NodeType.endpoint, NodeType.technology, NodeType.ip, NodeType.certificate} <= types


def test_cert_links_two_hosts(repo):
    svc = IngestService(repo)
    svc.ingest(get_importer("httpx").parse(HTTPX))
    cert_id = make_id(NodeType.certificate, "*.example.com")
    _, hosts = repo.neighbors(cert_id, types=[NodeType.subdomain.value])
    values = {h.value for h in hosts}
    assert {"api.example.com", "admin.example.com"} <= values


def test_reimport_is_idempotent(repo):
    svc = IngestService(repo)
    svc.ingest(get_importer("httpx").parse(HTTPX))
    before = repo.digest()["total_nodes"]
    svc.ingest(get_importer("httpx").parse(HTTPX))
    assert repo.digest()["total_nodes"] == before


def test_httpx_then_dnsx_enriches_one_node(repo):
    svc = IngestService(repo)
    svc.ingest(get_importer("httpx").parse(HTTPX))
    svc.ingest(get_importer("dnsx").parse(DNSX))
    host = repo.get_node(make_id(NodeType.subdomain, "api.example.com"))
    assert set(host.sources) == {"httpx", "dnsx"}
    ip = repo.get_node(make_id(NodeType.ip, "203.0.113.10"))
    assert ip.props.get("ptr") == "host.cloud"


def test_status_state_machine():
    assert can_transition(Status.untriaged, Status.in_scope)
    assert not can_transition(Status.untriaged, Status.confirmed)
    assert can_transition(Status.flagged, Status.confirmed)
