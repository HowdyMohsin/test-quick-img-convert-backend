"""Admin ops tests: popups/announcements aliases, jobs queue, reports
overview, formats shape + toggle, plan archive, settings site_url
fallback. Uses the conftest client (throwaway SQLite per test)."""

import asyncio
from datetime import date, timedelta
from types import SimpleNamespace

from conftest import csrf_headers, login_super

from app.routers_admin import _all_settings, _success_rate


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


def test_settings_site_url_empty_row_falls_back_to_env(monkeypatch):
    """A site_url row saved empty must not block the SITE_URL fallback.

    Regression: the fallback only triggered when the row was missing
    (``is None``), so one save from the empty General form persisted
    "" and the field stayed empty forever.
    """

    class _StubDb:
        def __init__(self, values):
            self.values = values

        async def get(self, model, key):
            if key in self.values:
                return SimpleNamespace(value=self.values[key])
            return None

    monkeypatch.setenv("SITE_URL", "https://example.test")
    body = asyncio.run(_all_settings(_StubDb({"site_url": ""})))
    assert body["site_url"] == "https://example.test"


def test_settings_site_url_blank_save_falls_back_to_env(client, monkeypatch):
    login_super(client)
    headers = csrf_headers(client)
    monkeypatch.setenv("SITE_URL", "https://example.test")
    # Saving a blank Site URL drops the row instead of persisting "",
    # so the aggregate still returns the env value afterwards.
    resp = client.patch("/admin/settings", json={"site_url": ""}, headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["site_url"] == "https://example.test"
    assert client.get("/admin/settings").json()["site_url"] == "https://example.test"


def test_settings_site_url_unset_env_returns_none(client, monkeypatch):
    login_super(client)
    monkeypatch.delenv("SITE_URL", raising=False)
    assert client.get("/admin/settings").json()["site_url"] is None


def test_settings_site_url_db_value_wins_over_env(client, monkeypatch):
    login_super(client)
    headers = csrf_headers(client)
    monkeypatch.setenv("SITE_URL", "https://example.test")
    resp = client.patch("/admin/settings", json={"site_url": "https://db.example"},
                        headers=headers)
    assert resp.status_code == 200, resp.text
    assert client.get("/admin/settings").json()["site_url"] == "https://db.example"


def test_success_rate_helper():
    # Queued-only: no finished jobs, nothing failed -> 100.0.
    assert _success_rate(0, 0) == 100.0
    assert _success_rate(0, 1) == 0.0
    assert _success_rate(1, 0) == 100.0
    assert _success_rate(5, 1) == 83.3
    assert _success_rate(2, 2) == 50.0


def test_dashboard_and_reports_success_rate_agree(client):
    login_super(client)
    headers = csrf_headers(client)
    # Seeded: 5 done + 1 failed today, 1 done yesterday.
    dash = client.get("/admin/dashboard").json()
    assert dash["kpis"]["success_rate"] == 83.3
    assert dash["kpis"]["conversions_today"] == 6
    # Reports over 30 days: 6 done / (6 done + 1 failed).
    assert client.get("/admin/reports").json()["totals"]["success_rate"] == 85.7
    # Re-queue the one failed job: today is now 5 done + 1 queued, no
    # failures. The queued job must not drag the rate down, and both
    # endpoints must agree (old reports code gave done/total = 85.7).
    failed = client.get("/admin/jobs?status=failed").json()["items"]
    assert len(failed) == 1
    resp = client.post(f"/admin/jobs/{failed[0]['id']}/retry", json={}, headers=headers)
    assert resp.status_code == 200, resp.text
    dash = client.get("/admin/dashboard").json()
    reports = client.get("/admin/reports").json()
    assert dash["kpis"]["success_rate"] == 100.0
    assert reports["totals"]["success_rate"] == 100.0


def test_user_detail_usage_shape(client):
    login_super(client)
    body = client.get(f"/admin/users/{client.user_id}").json()
    # Seeded user: 5 done + 1 failed today, 1 done yesterday; plan free.
    assert body["usage"] == {"today": {"used": 6, "limit": 25}, "month": {"used": 7}}


def test_users_list_usage_today(client):
    login_super(client)
    body = client.get("/admin/users").json()
    assert body["total"] == 1
    assert body["items"][0]["usage_today"] == {"used": 6, "limit": 25}
