"""Admin API tests: dashboard, users, team, settings, reports, audit log."""

from conftest import (
    STAFF_EMAIL,
    STAFF_PASSWORD,
    USER_EMAIL,
    csrf_headers,
    login_as,
    login_super,
)


def test_unauthenticated_admin_api_returns_standard_error(client):
    resp = client.get("/admin/dashboard")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "admin_auth_required"


def test_dashboard_returns_kpi_shape(client):
    login_super(client)
    resp = client.get("/admin/dashboard")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    kpis = body["kpis"]
    assert kpis["users"] == 1
    assert kpis["conversions_today"] == 6  # 5 done + 1 failed today
    assert kpis["success_rate"] == 83.3
    assert kpis["active_subscriptions"] == 1
    assert kpis["mrr_cents"] == 400  # basic monthly
    assert kpis["pending_approvals"] == 1
    assert len(body["chart_30d"]) == 30
    assert body["top_pairs"][0]["pair_slug"] == "jpg-to-png"
    assert len(body["recent_errors"]) == 1
    assert body["recent_errors"][0]["error_code"] == "engine_missing"
    assert body["disabled_pair_alerts"][0]["pair_slug"] == "heic-to-jpg"


def test_staff_without_section_permission_gets_403(client):
    login_as(client, STAFF_EMAIL, STAFF_PASSWORD)
    assert client.get("/admin/dashboard").status_code == 200
    resp = client.get("/admin/users")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "admin_forbidden"
    resp = client.get("/admin/reports/conversions")
    assert resp.status_code == 403


def test_users_list_search_and_pagination(client):
    login_super(client)
    resp = client.get("/admin/users?q=user@example")
    assert resp.status_code == 200
    assert resp.json()["total"] == 1
    assert resp.json()["items"][0]["email"] == USER_EMAIL
    resp = client.get("/admin/users?q=nobody")
    assert resp.json()["total"] == 0
    resp = client.get("/admin/users?plan=pro")
    assert resp.json()["total"] == 0
    resp = client.get("/admin/users?plan=free")
    assert resp.json()["total"] == 1


def test_user_detail_shape(client):
    login_super(client)
    resp = client.get(f"/admin/users/{client.user_id}")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["usage"] == {"today": {"used": 6, "limit": 25}, "month": {"used": 7}}
    assert body["subscription"]["plan_id"] == "basic"
    assert len(body["payment_requests"]) == 2
    assert len(body["payments"]) == 1
    assert body["payments"][0]["receipt_no"] == "QIC-2026-000001"
    assert len(body["jobs"]) == 7
    assert body["notes"] == ""


def test_ban_with_reason_revokes_user_sessions(client):
    login_super(client)
    resp = client.post(
        f"/admin/users/{client.user_id}/ban",
        json={"reason": "payment fraud"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["sessions_revoked"] == 1
    assert resp.json()["user"]["banned"] is True
    # The user's sessions are revoked; detail shows the revoked session.
    detail = client.get(f"/admin/users/{client.user_id}").json()
    assert detail["sessions"][0]["revoked"] is True
    # Unban requires a reason too.
    resp = client.post(
        f"/admin/users/{client.user_id}/unban",
        json={"reason": "appeal accepted"},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 200
    assert resp.json()["user"]["banned"] is False


def test_ban_without_reason_is_rejected(client):
    login_super(client)
    resp = client.post(
        f"/admin/users/{client.user_id}/ban",
        json={"reason": "   "},
        headers=csrf_headers(client),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "reason_required"


def test_audit_log_row_written_with_before_after_on_mutation(client):
    login_super(client)
    client.post(
        f"/admin/users/{client.user_id}/ban",
        json={"reason": "audit check"},
        headers=csrf_headers(client),
    )
    resp = client.get("/admin/audit?action=users.ban")
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) == 1
    row = items[0]
    assert row["admin_email"] == "admin@qic.local"
    assert row["target"] == client.user_id
    assert row["before"]["banned"] is False
    assert row["after"]["banned"] is True
    assert row["after"]["ban_reason"] == "audit check"
    assert row["diff"]["banned"]["before"] is False
    assert row["diff"]["banned"]["after"] is True
    # CSV export works and contains the action.
    csv_resp = client.get("/admin/audit/export")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "users.ban" in csv_resp.text


def test_change_plan_extend_cancel_and_notes(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post(
        f"/admin/users/{client.user_id}/change-plan",
        json={"plan": "pro", "reason": "goodwill upgrade", "complimentary_days": 30},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["plan"] == "pro"
    resp = client.post(
        f"/admin/users/{client.user_id}/extend-period",
        json={"days": 15, "reason": "compensation"},
        headers=headers,
    )
    assert resp.status_code == 200
    resp = client.post(
        f"/admin/users/{client.user_id}/cancel-subscription",
        json={"reason": "user asked to cancel"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["subscription"]["cancel_at_period_end"] is True
    resp = client.post(
        f"/admin/users/{client.user_id}/force-signout",
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["signed_out_sessions"] == 1
    resp = client.patch(
        f"/admin/users/{client.user_id}/notes",
        json={"notes": "VIP customer, handle with care."},
        headers=headers,
    )
    assert resp.status_code == 200
    detail = client.get(f"/admin/users/{client.user_id}").json()
    assert detail["notes"] == "VIP customer, handle with care."


def test_team_crud_and_reset_link(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post(
        "/admin/team",
        json={
            "email": "newstaff@qic.local",
            "password": "NewStaffPass123",
            "role": "staff",
            "permissions": {"users": ["read"]},
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    member = resp.json()
    assert member["must_change_password"] is True  # forced change at first login
    assert member["role"] == "staff"
    resp = client.post(
        f"/admin/team/{member['id']}/reset-link", headers=headers
    )
    assert resp.status_code == 200
    assert "/admin/reset-password?token=" in resp.json()["reset_link"]
    resp = client.patch(
        f"/admin/team/{member['id']}",
        json={"permissions": {"users": ["read", "write"], "dashboard": ["read"]}},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["permissions"]["users"] == ["read", "write"]
    resp = client.delete(f"/admin/team/{member['id']}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    # Cannot delete your own account.
    me = client.get("/admin/auth/me").json()
    resp = client.delete(f"/admin/team/{me['id']}", headers=headers)
    assert resp.status_code == 422
    # Bad permission section is rejected.
    resp = client.post(
        "/admin/team",
        json={"email": "bad@qic.local", "password": "BadStaffPass123",
              "role": "staff", "permissions": {"nope": ["read"]}},
        headers=headers,
    )
    assert resp.status_code == 422


def test_settings_general_and_limits(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.patch(
        "/admin/settings/general",
        json={"pkr_per_usd": 280.0, "support_email": "support@qic.local",
              "approval_window_text": "Approved within 24 hours"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["pkr_per_usd"] == 280.0
    resp = client.get("/admin/settings/general")
    assert resp.json()["support_email"] == "support@qic.local"
    assert resp.json()["quota_tz"] == "Asia/Karachi"
    resp = client.patch(
        "/admin/settings/general",
        json={"pkr_per_usd": -5},
        headers=headers,
    )
    assert resp.status_code == 422
    resp = client.patch(
        "/admin/settings/limits",
        json={"retention_hours": 48, "upload_rate_per_min": 60},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["retention_hours"] == 48


def test_settings_aggregate_endpoint(client):
    # The admin General/Limits pages call the single /admin/settings
    # endpoint (previously missing -> 404); it merges general + limits
    # and accepts the pages' field names (quota_timezone, max_batch,
    # max_file_mb) as aliases of the canonical keys.
    login_super(client)
    headers = csrf_headers(client)
    resp = client.get("/admin/settings")
    assert resp.status_code == 200, resp.text
    assert resp.json()["quota_tz"] == "Asia/Karachi"
    assert resp.json()["quota_timezone"] == "Asia/Karachi"
    assert resp.json()["retention_hours"] == 24
    assert resp.json()["approval_window_hours"] == 24
    resp = client.patch(
        "/admin/settings",
        json={"quota_timezone": "Europe/London", "max_batch": 50,
              "max_file_mb": 1024, "approval_window_hours": 12},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["quota_tz"] == "Europe/London"
    assert body["quota_timezone"] == "Europe/London"
    assert body["max_batch_files"] == 50
    assert body["max_batch"] == 50
    assert body["max_upload_mb"] == 1024
    assert body["max_file_mb"] == 1024
    assert body["approval_window_hours"] == 12
    # The section endpoints read the same canonical keys.
    resp = client.get("/admin/settings/general")
    assert resp.json()["quota_tz"] == "Europe/London"
    resp = client.get("/admin/settings/limits")
    assert resp.json()["max_batch_files"] == 50
    assert resp.json()["max_upload_mb"] == 1024
    # Validation mirrors the section endpoints.
    resp = client.patch("/admin/settings", json={"pkr_per_usd": -1}, headers=headers)
    assert resp.status_code == 422
    resp = client.patch("/admin/settings", json={"quota_timezone": "Not/AZone"}, headers=headers)
    assert resp.status_code == 422


def test_settings_email_placeholders_and_smtp_check_shape(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.get("/admin/settings/email")
    assert resp.status_code == 200
    assert "{name}" in resp.json()["placeholders"]
    assert "{reference}" in resp.json()["placeholders"]
    resp = client.patch(
        "/admin/settings/email",
        json={"templates": [
            {"key": "welcome", "subject": "Welcome {name}",
             "body": "Hi {name}, your plan is {plan}."}
        ]},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    resp = client.patch(
        "/admin/settings/email",
        json={"templates": [
            {"key": "welcome", "subject": "Hi", "body": "Hello {unknown}!"}
        ]},
        headers=headers,
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "invalid_placeholder"
    # SMTP is not configured in this environment: the check fails cleanly
    # in the standard error shape instead of hanging or crashing.
    resp = client.post("/admin/settings/email/test", headers=headers)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "smtp_not_configured"


def test_settings_legal_markdown(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.patch(
        "/admin/settings/legal",
        json={"legal_privacy": "# Privacy\nFiles are deleted after 24 hours.",
              "legal_terms": "# Terms\nBe kind."},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    resp = client.get("/admin/settings/legal")
    assert resp.json()["legal_privacy"].startswith("# Privacy")


def test_reports_and_csv_export(client):
    login_super(client)
    resp = client.get("/admin/reports/conversions")
    assert resp.status_code == 200, resp.text
    assert resp.json()["summary"]["conversions"] == 7
    assert resp.json()["summary"]["failed"] == 1
    resp = client.get("/admin/reports/revenue")
    assert resp.status_code == 200
    assert resp.json()["total_revenue_cents"] == 900
    assert resp.json()["by_provider"][0]["provider_key"] == "easypaisa"
    assert resp.json()["mrr_cents"] == 400
    resp = client.get("/admin/reports/funnel")
    assert resp.status_code == 200
    assert resp.json()["anonymous_conversions"] == 2
    assert resp.json()["total_users"] == 1
    resp = client.get("/admin/reports/top-pairs")
    assert resp.json()["top_pairs"][0] == {
        "pair_slug": "jpg-to-png", "conversions": 6}
    resp = client.get("/admin/reports/errors")
    assert resp.json()["by_error_code"][0]["error_code"] == "engine_missing"
    csv_resp = client.get("/admin/reports/export?type=top-pairs")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "jpg-to-png" in csv_resp.text
    resp = client.get("/admin/reports/export?type=nope")
    assert resp.status_code == 422


def test_danger_purge_and_export(client):
    login_super(client)
    headers = csrf_headers(client)
    resp = client.post("/admin/settings/danger/purge", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["jobs_purged"] == 0  # nothing past retention yet
    resp = client.get("/admin/settings/danger/export")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-type"] or "json" in resp.headers["content-type"]
    assert USER_EMAIL in resp.text
    assert "password_hash" not in resp.text
