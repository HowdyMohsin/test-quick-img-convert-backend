"""Admin ops tests: popups/announcements aliases, jobs queue, reports
overview, formats shape + toggle, plan archive, settings site_url
fallback. Uses the conftest client (throwaway SQLite per test)."""

from datetime import date, timedelta

from conftest import csrf_headers, login_super


def _dates(days_back=29):
    today = date.today()
    return (today - timedelta(days=days_back)).isoformat(), today.isoformat()


def test_popups_alias_routes(client):
    login_super(client)
    headers = csrf_headers(client)
    # No popups seeded in this harness: the list is empty but 200.
    assert client.get("/admin/popups").json() == {"popups": []}
    # Full upsert on the legacy /admin/ads prefix (the admin page uses it).
    resp = client.put("/admin/ads/popups/limit_popup", json={
        "key": "limit_popup", "enabled": True, "title": "Daily limit reached",
        "body": "You are out of conversions.", "cta_text": "See plans",
        "cta_href": "/pricing", "frequency": "once per session",
        "pages": ["/", "/convert"],
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    # The /admin alias serves the same row.
    rows = client.get("/admin/popups").json()["popups"]
    assert len(rows) == 1
    assert rows[0]["key"] == "limit_popup"
    assert rows[0]["title"] == "Daily limit reached"
    assert rows[0]["pages"] == ["/", "/convert"]
    # PUT under /admin works without the key in the body.
    resp = client.put("/admin/popups/exit_popup", json={
        "enabled": True, "title": "Before you go",
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    # PATCH toggle (the admin page's switch sends {enabled} only).
    resp = client.patch("/admin/popups/limit_popup", json={"enabled": False},
                        headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["enabled"] is False
    rows = client.get("/admin/ads/popups").json()["popups"]
    assert {r["key"]: r["enabled"] for r in rows} == {
        "exit_popup": True, "limit_popup": False}


def test_announcements_alias_routes(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post("/admin/announcements", json={
        "text": "Welcome to Quick IMG Convert.", "enabled": True,
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["text"] == "Welcome to Quick IMG Convert."
    anns = client.get("/admin/announcements").json()["announcements"]
    assert len(anns) == 1
    assert anns[0]["text"] == "Welcome to Quick IMG Convert."
    # The legacy prefix serves the same row.
    assert client.get("/admin/ads/announcements").json()["announcements"] == anns


def test_admin_jobs_list_and_filter(client):
    login_super(client)
    body = client.get("/admin/jobs").json()
    assert body["total"] == 7
    assert len(body["items"]) == 7
    assert body["items"][0]["pair_slug"] == "jpg-to-png"
    assert body["items"][0]["status"] == "done"
    assert body["items"][0]["progress"] == 0
    failed = client.get("/admin/jobs?status=failed").json()
    assert failed["total"] == 1
    assert failed["items"][0]["pair_slug"] == "mp3-to-wav"
    assert failed["items"][0]["error_message"] == "ffmpeg not available"
    # The page filters with `canceled` (one L); the DB stores `cancelled`.
    assert client.get("/admin/jobs?status=canceled").json()["total"] == 0


def test_admin_jobs_retry_then_cancel(client):
    login_super(client)
    headers = csrf_headers(client)
    failed_id = client.get("/admin/jobs?status=failed").json()["items"][0]["id"]
    resp = client.post(f"/admin/jobs/{failed_id}/retry", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["job"]["status"] == "queued"
    resp = client.post(f"/admin/jobs/{failed_id}/cancel", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["job"]["status"] == "cancelled"
    assert resp.json()["refunded"] is True
    assert client.get("/admin/jobs?status=canceled").json()["total"] == 1


def test_admin_jobs_purge_expired(client):
    login_super(client)
    resp = client.post("/admin/jobs/purge-expired", json={},
                       headers=csrf_headers(client))
    assert resp.status_code == 200, resp.text
    assert resp.json()["purged"] == 0


def test_admin_reports_overview(client):
    login_super(client)
    start, end = _dates()
    resp = client.get(f"/admin/reports?from={start}&to={end}")
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["totals"]["conversions"] == 7
    assert d["totals"]["successful"] == 6
    assert d["totals"]["failed"] == 1
    assert d["totals"]["success_rate"] == 85.7
    assert d["totals"]["bytes_in"] == 8000
    assert d["totals"]["bytes_out"] == 2300
    assert d["totals"]["mrr_cents"] == 400  # basic monthly subscription
    assert len(d["daily"]) == 30
    assert d["daily"][-1]["conversions"] == 6  # today: 5 done + 1 failed
    assert d["top_pairs"][0]["pair_slug"] == "jpg-to-png"
    assert d["top_pairs"][0]["count"] == 6
    assert d["engine_errors"] == [
        {"error_code": "engine_missing", "code": "engine_missing",
         "pair_slug": "mp3-to-wav", "count": 1}]
    assert d["revenue_by_provider"] == [
        {"provider_key": "easypaisa", "plan": "pro", "amount_cents": 900}]
    assert d["funnel"]["anonymous"] == 2
    assert d["funnel"]["free"] == 1
    assert d["funnel"]["paid"] == 1


def test_admin_reports_empty_range(client):
    login_super(client)
    resp = client.get("/admin/reports?from=2020-01-01&to=2020-01-02")
    assert resp.status_code == 200, resp.text
    d = resp.json()
    assert d["totals"]["conversions"] == 0
    assert d["totals"]["success_rate"] == 100.0
    assert len(d["daily"]) == 2
    assert d["top_pairs"] == []
    assert d["engine_errors"] == []
    assert d["revenue_by_provider"] == []


def test_admin_formats_shape_and_toggle(client):
    login_super(client)
    resp = client.get("/admin/formats")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 238
    assert len(body["pairs"]) == 238
    jpg_png = next(p for p in body["pairs"] if p["pair_slug"] == "jpg-to-png")
    assert jpg_png["from_slug"] == "jpg"
    assert jpg_png["to_slug"] == "png"
    assert jpg_png["status"] == "healthy"
    assert all("pair_slug" in p and "from_slug" in p and "to_slug" in p
               and "status" in p for p in body["pairs"])
    # Toggle via PATCH /admin/formats/{pair_slug} {status}.
    headers = csrf_headers(client)
    resp = client.patch("/admin/formats/jpg-to-png", json={"status": "disabled"},
                        headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "disabled"
    rows = client.get("/admin/formats").json()["pairs"]
    assert next(p for p in rows if p["pair_slug"] == "jpg-to-png")["status"] == "disabled"
    resp = client.patch("/admin/formats/jpg-to-png", json={"status": "healthy"},
                        headers=headers)
    assert resp.json()["status"] == "healthy"
    assert client.patch("/admin/formats/nope-to-nope", json={"status": "disabled"},
                        headers=headers).status_code == 404


def test_admin_formats_make_sample(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post("/admin/formats/make-sample", json={"format": "jpg"},
                       headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["format"] == "jpg"
    assert "generated" in resp.json()["message"]
    assert client.post("/admin/formats/make-sample", json={"format": "nope"},
                       headers=headers).status_code == 404


def test_plan_archive_roundtrip_and_audit(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post("/admin/plans", json={
        "id": "test-plan", "name": "Test Plan", "price_cents": 100,
        "price_yearly_cents": 1000,
    }, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["plan"]["archived"] is False
    resp = client.post("/admin/plans/test-plan/archive", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["plan"]["archived"] is True
    assert resp.json()["plan"]["active"] is False
    audit = client.get("/admin/audit?action=plan.archive").json()
    assert audit["total"] == 1
    assert audit["items"][0]["target"] == "plan:test-plan"


def test_settings_site_url_falls_back_to_env(client, monkeypatch):
    login_super(client)
    monkeypatch.setenv("SITE_URL", "https://example.test")
    body = client.get("/admin/settings").json()
    assert body["site_url"] == "https://example.test"
