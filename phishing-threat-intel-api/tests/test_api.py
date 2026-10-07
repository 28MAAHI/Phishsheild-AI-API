from sqlalchemy.exc import OperationalError

from threatintel.api import routes
from threatintel.api.deps import get_db
from tests.conftest import ADMIN_KEY, make_client, make_settings

ADMIN = {"X-API-Key": ADMIN_KEY}


def assert_error(resp, status, code):
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert body["success"] is False and body["error"]["code"] == code
    assert "Traceback" not in resp.text
    return body


# ── Health ───────────────────────────────────────────────────────────────

def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["status"] == "ok" and data["database"] == "ok" and data["scheduler"] == "disabled"


def test_health_reports_database_down(client):
    class DeadSession:
        def execute(self, *a, **kw):
            raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    client.app.dependency_overrides[get_db] = lambda: DeadSession()
    r = client.get("/api/health")
    assert r.status_code == 503
    assert r.json()["data"]["database"] == "unavailable" and "connection refused" not in r.text


# ── Listing / pagination ─────────────────────────────────────────────────

def test_list_urls_envelope(client, seeded):
    r = client.get("/api/urls")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True and body["count"] == 4 and len(body["data"]) == 4
    assert body["pagination"] == {"page": 1, "limit": 50, "total": 4, "total_pages": 1, "has_next": False}
    item = body["data"][0]
    for key in ("id", "url", "domain", "hostname", "sources", "threat_type", "confidence", "first_seen", "last_seen"):
        assert key in item
    assert "url_hash" not in item and "sightings" not in item


def test_pagination(client, seeded):
    p1 = client.get("/api/urls?limit=3&page=1").json()
    p2 = client.get("/api/urls?limit=3&page=2").json()
    assert p1["count"] == 3 and p1["pagination"]["has_next"] is True and p1["pagination"]["total_pages"] == 2
    assert p2["count"] == 1 and p2["pagination"]["has_next"] is False
    assert not {u["id"] for u in p1["data"]} & {u["id"] for u in p2["data"]}
    assert client.get("/api/urls?limit=3&page=9").json()["data"] == []


def test_page_size_limits(client, seeded):
    assert_error(client.get("/api/urls?limit=101"), 422, "invalid_request")  # PAGE_SIZE_MAX=100 in tests
    assert_error(client.get("/api/urls?limit=0"), 422, "invalid_request")
    assert_error(client.get("/api/urls?page=0"), 422, "invalid_request")
    assert_error(client.get("/api/urls?page=abc"), 422, "invalid_request")


def test_filters(client, seeded):
    def total(q):
        r = client.get("/api/urls?" + q)
        assert r.status_code == 200, r.text
        return r.json()["pagination"]["total"]

    assert total("source=beta") == 2
    assert total("source=BETA") == 2
    assert total("source=unknown") == 0
    assert total("threat_type=phishing") == 3
    assert total("threat_type=malware_download") == 2
    assert total("domain=example.com") == 1          # login.example.com via registrable domain
    assert total("domain=login.example.com") == 1     # exact hostname
    assert total("hostname=files.example.net") == 1
    assert total("status=offline") == 1
    assert total("since=2000-01-01T00:00:00Z") == 4
    assert total("since=2999-01-01T00:00:00Z") == 0
    assert total("source=beta&threat_type=phishing") == 0


def test_invalid_filters(client, seeded):
    body = assert_error(client.get("/api/urls?domain=http://x.com/"), 422, "invalid_domain")
    assert body["error"]["details"][0]["field"] == "domain"
    assert_error(client.get("/api/urls?sort=password"), 422, "invalid_request")
    assert_error(client.get("/api/urls?since=yesterday"), 422, "invalid_request")
    assert_error(client.get("/api/urls?since=2026-02-01T00:00:00Z&until=2026-01-01T00:00:00Z"), 422, "invalid_request")


def test_sorting(client, seeded):
    asc = [u["id"] for u in client.get("/api/urls?sort=id").json()["data"]]
    desc = [u["id"] for u in client.get("/api/urls?sort=-id").json()["data"]]
    assert asc == sorted(asc) and desc == asc[::-1]


# ── Details / latest / lookup ────────────────────────────────────────────

def test_url_details(client, seeded):
    target = next(u for u in client.get("/api/urls").json()["data"] if u["hostname"] == "login.example.com")
    r = client.get(f"/api/urls/{target['id']}")
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["url"] == "https://login.example.com/verify"
    assert data["sources"] == ["alpha", "beta"]
    assert {s["source"] for s in data["sightings"]} == {"alpha", "beta"}
    alpha = next(s for s in data["sightings"] if s["source"] == "alpha")
    assert alpha["source_reference"] == "a-1" and alpha["tags"] == ["bank"] and alpha["metadata"] == {"note": "synthetic"}
    assert data["tags"] == ["bank", "kit"] and set(data["threat_types"]) == {"phishing", "malware_download"}


def test_confidence_only_when_provided(client, seeded):
    by_host = {u["url"]: u for u in client.get("/api/urls").json()["data"]}
    assert by_host["https://example.org/signin?session=1"]["confidence"] == 0.9
    assert by_host["https://login.example.com/verify"]["confidence"] is None


def test_missing_record(client, seeded):
    assert_error(client.get("/api/urls/999999"), 404, "not_found")
    assert_error(client.get("/api/urls/abc"), 422, "invalid_request")
    assert_error(client.get("/api/urls/0"), 422, "invalid_request")


def test_latest(client, seeded):
    r = client.get("/api/urls/latest?limit=2")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 2 and body["pagination"]["total"] == 4
    created = [u["created_at"] for u in body["data"]]
    assert created == sorted(created, reverse=True)
    assert client.get("/api/urls/latest?since=2999-01-01T00:00:00Z").json()["count"] == 0


def test_lookup(client, seeded):
    found = client.get("/api/urls/lookup", params={"url": "HTTPS://Login.Example.com:443/verify#x"}).json()["data"]
    assert found["found"] is True and found["normalized_url"] == "https://login.example.com/verify"
    assert len(found["record"]["sightings"]) == 2
    missing = client.get("/api/urls/lookup", params={"url": "https://not-collected.example.com/"}).json()["data"]
    assert missing == {"found": False, "normalized_url": "https://not-collected.example.com/", "record": None}
    assert_error(client.get("/api/urls/lookup", params={"url": "ftp://x.com"}), 422, "invalid_url")
    assert_error(client.get("/api/urls/lookup"), 422, "invalid_request")


# ── Domains / stats / sources ────────────────────────────────────────────

def test_domain(client, seeded):
    r = client.get("/api/domains/Example.NET")
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["summary"]["domain"] == "example.net" and data["summary"]["url_count"] == 2
    assert data["summary"]["hostname_count"] == 2
    assert len(data["urls"]) == 2 and data["pagination"]["total"] == 2
    assert_error(client.get("/api/domains/unknown-domain.com"), 404, "not_found")
    assert_error(client.get("/api/domains/not_a_domain"), 422, "invalid_domain")


def test_stats(client, seeded):
    data = client.get("/api/stats").json()["data"]
    assert data["total_urls"] == 4 and data["distinct_domains"] == 3
    assert data["by_source"] == {"alpha": 3, "beta": 2}
    assert data["urls_added_last_24h"] == 4


def test_stats_empty_database(client):
    data = client.get("/api/stats").json()["data"]
    assert data["total_urls"] == 0 and data["newest_url_added_at"] is None


def test_sources(client, seeded):
    data = client.get("/api/sources").json()["data"]
    assert [s["name"] for s in data] == ["alpha", "beta"]
    assert data[0]["enabled"] and data[0]["configured"] and data[0]["last_run"]["status"] == "succeeded"


# ── Manual collection ────────────────────────────────────────────────────

def test_collect_requires_admin_key(client):
    assert_error(client.post("/api/collect", json={}), 401, "unauthorized")
    assert_error(client.post("/api/collect", json={}, headers={"X-API-Key": "wrong"}), 401, "unauthorized")


def test_collect_disabled_without_admin_key(service):
    with make_client(make_settings(admin_api_key=None), service) as c:
        assert_error(c.post("/api/collect", json={}), 403, "collect_disabled")


def test_collect_wait(client):
    r = client.post("/api/collect", json={"sources": ["alpha"], "wait": True}, headers=ADMIN)
    assert r.status_code == 200
    res = r.json()["data"][0]
    assert res["source"] == "alpha" and res["status"] == "succeeded" and res["new"] == 3 and res["invalid"] == 1
    assert client.get("/api/urls").json()["pagination"]["total"] == 3


def test_collect_background_and_run_status(client):
    r = client.post("/api/collect", headers=ADMIN)
    assert r.status_code == 202
    started = r.json()["data"]
    assert {s["status"] for s in started} == {"running"}
    # TestClient executes background tasks before returning, so runs are finished now.
    run = client.get(f"/api/collect/runs/{started[0]['run_id']}").json()["data"]
    assert run["status"] == "succeeded" and run["records_new"] == 3
    runs = client.get("/api/collect/runs?source=alpha").json()
    assert runs["pagination"]["total"] == 1
    assert_error(client.get("/api/collect/runs/424242"), 404, "not_found")


def test_collect_min_interval_and_force(client):
    client.post("/api/collect", json={"sources": ["alpha"], "wait": True}, headers=ADMIN)
    skipped = client.post("/api/collect", json={"sources": ["alpha"], "wait": True}, headers=ADMIN).json()["data"][0]
    assert skipped["status"] == "skipped" and skipped["reason"] == "min_interval"
    forced = client.post("/api/collect", json={"sources": ["alpha"], "wait": True, "force": True},
                         headers=ADMIN).json()["data"][0]
    assert forced["status"] == "succeeded" and forced["new"] == 0 and forced["existing"] == 3


def test_collect_invalid_requests(client):
    assert_error(client.post("/api/collect", json={"sources": ["nope"]}, headers=ADMIN), 400, "unknown_source")
    assert_error(client.post("/api/collect", json={"unexpected": 1}, headers=ADMIN), 422, "invalid_request")
    assert_error(client.post("/api/collect", json={"sources": "alpha"}, headers=ADMIN), 422, "invalid_request")
    assert_error(client.post("/api/collect", content="{bad json", headers={**ADMIN, "Content-Type": "application/json"}),
                 422, "invalid_request")


# ── Failures / security ──────────────────────────────────────────────────

def test_database_failure_returns_503(client, monkeypatch):
    def boom(*a, **kw):
        raise OperationalError("SELECT secret_table", {}, Exception("password=hunter2"))

    monkeypatch.setattr(routes.repository, "list_urls", boom)
    body = assert_error(client.get("/api/urls"), 503, "database_unavailable")
    assert "hunter2" not in str(body) and "secret_table" not in str(body)


def test_unexpected_error_returns_generic_500(settings, service, monkeypatch):
    monkeypatch.setattr(routes.repository, "stats", lambda *a, **k: 1 / 0)
    with make_client(settings, service, raise_server_exceptions=False) as c:
        body = assert_error(c.get("/api/stats"), 500, "internal_error")
    assert "ZeroDivision" not in str(body)


def test_unknown_route_and_method(client):
    assert_error(client.get("/api/does-not-exist"), 404, "not_found")
    assert_error(client.delete("/api/urls"), 405, "method_not_allowed")


def test_read_api_keys_enforced_when_configured(service):
    with make_client(make_settings(read_api_keys="reader-1,reader-2"), service) as c:
        assert_error(c.get("/api/urls"), 401, "unauthorized")
        assert c.get("/api/urls", headers={"X-API-Key": "reader-2"}).status_code == 200
        assert c.get("/api/urls", headers=ADMIN).status_code == 200
        assert c.get("/api/health").status_code == 200  # health stays public


def test_rate_limit(service):
    with make_client(make_settings(rate_limit_default="3/minute"), service) as c:
        codes = [c.get("/api/stats").status_code for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        r = c.get("/api/stats")
        assert_error(r, 429, "rate_limited")
        assert int(r.headers["Retry-After"]) >= 1


def test_openapi_docs_available(client):
    spec = client.get("/openapi.json").json()
    for path in ("/api/health", "/api/urls", "/api/urls/latest", "/api/urls/{url_id}", "/api/urls/lookup",
                 "/api/domains/{domain}", "/api/stats", "/api/sources", "/api/collect", "/api/collect/runs"):
        assert path in spec["paths"]
    assert client.get("/docs").status_code == 200
