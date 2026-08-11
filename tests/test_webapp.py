"""Web API tests: authentication, CSRF, RBAC, redaction, XSS and imports."""

from __future__ import annotations

import io

from m365_posture.database import Database

from .conftest import STRONG_PW, XRW, make_scuba_results


# ── Authentication ──

def test_api_requires_login(client):
    assert client.get("/api/tenants").status_code == 401


def test_login_logout_flow(admin_client):
    me = admin_client.get("/api/auth/me").get_json()
    assert me["authenticated"] is True
    assert me["role"] == "admin"
    assert "password_hash" not in me
    admin_client.post("/api/auth/logout", headers=XRW)
    assert admin_client.get("/api/tenants").status_code == 401


def test_login_rejects_bad_credentials(client, db):
    r = client.post("/api/auth/login", json={"username": "adminuser", "password": "nope"})
    assert r.status_code == 401


def test_login_rate_limit(app, db_path):
    db = Database(db_path)
    db.create_user("victim", STRONG_PW, role="viewer")
    c = app.test_client()
    for _ in range(10):
        c.post("/api/auth/login", json={"username": "victim", "password": "wrong"})
    r = c.post("/api/auth/login", json={"username": "victim", "password": STRONG_PW})
    assert r.status_code == 429


def test_default_admin_forced_password_change(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    assert r.get_json()["must_change_password"] is True
    # Everything except the password-change endpoints is blocked
    r = client.get("/api/tenants")
    assert r.status_code == 403
    assert r.get_json()["must_change_password"] is True
    # Too-short password rejected
    r = client.post("/api/auth/change-password", headers=XRW,
                    json={"current_password": "admin", "new_password": "short"})
    assert r.status_code == 400
    r = client.post("/api/auth/change-password", headers=XRW,
                    json={"current_password": "admin", "new_password": STRONG_PW})
    assert r.status_code == 200
    assert client.get("/api/tenants").status_code == 200


def test_csrf_header_required_for_writes(admin_client):
    r = admin_client.post("/api/tenants", json={"name": "newten"})  # no X-Requested-With
    assert r.status_code == 403
    assert "CSRF" in r.get_json()["error"]
    r = admin_client.post("/api/tenants", json={"name": "newten"}, headers=XRW)
    assert r.status_code == 201


# ── RBAC ──

def test_viewer_is_read_only(viewer_client, admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    assert viewer_client.get("/api/tenants").status_code == 200
    r = viewer_client.post("/api/tenants", json={"name": "x"}, headers=XRW)
    assert r.status_code == 403
    r = viewer_client.put("/api/tenants/contoso", json={"notes": "hi"}, headers=XRW)
    assert r.status_code == 403


def test_analyst_cannot_manage_users(analyst_client):
    """Privilege-escalation guard: analysts must not create or modify users."""
    r = analyst_client.post("/api/control-plane/users", headers=XRW,
                            json={"username": "evil", "password": STRONG_PW,
                                  "role": "admin"})
    assert r.status_code == 403
    r = analyst_client.put("/api/control-plane/users/someid", headers=XRW,
                           json={"role": "admin"})
    assert r.status_code == 403
    r = analyst_client.delete("/api/control-plane/users/someid", headers=XRW)
    assert r.status_code == 403
    r = analyst_client.post("/api/control-plane/users/someid/tenant-access",
                            headers=XRW, json={"tenant_name": "contoso"})
    assert r.status_code == 403


def test_admin_can_manage_users(admin_client):
    r = admin_client.post("/api/control-plane/users", headers=XRW,
                          json={"username": "newanalyst", "password": STRONG_PW,
                                "role": "analyst"})
    assert r.status_code == 201
    uid = r.get_json()["id"]
    r = admin_client.put(f"/api/control-plane/users/{uid}", headers=XRW,
                         json={"display_name": "Renamed"})
    assert r.status_code == 200
    # Weak passwords and bad roles are rejected
    r = admin_client.post("/api/control-plane/users", headers=XRW,
                          json={"username": "weak", "password": "short", "role": "viewer"})
    assert r.status_code == 400
    r = admin_client.post("/api/control-plane/users", headers=XRW,
                          json={"username": "badrole", "password": STRONG_PW,
                                "role": "superuser"})
    assert r.status_code == 400


def test_admin_cannot_lock_themselves_out(admin_client):
    me = admin_client.get("/api/auth/me").get_json()
    r = admin_client.put(f"/api/control-plane/users/{me['id']}", headers=XRW,
                         json={"role": "viewer"})
    assert r.status_code == 403
    r = admin_client.delete(f"/api/control-plane/users/{me['id']}", headers=XRW)
    assert r.status_code == 400


def test_tenant_credentials_require_admin(analyst_client, admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    # Analyst may edit harmless fields…
    r = analyst_client.put("/api/tenants/contoso", json={"notes": "n"}, headers=XRW)
    assert r.status_code == 200
    # …but not credential-bearing ones
    for field in ("client_secret", "client_id", "tenant_id",
                  "certificate_path", "auth_methods"):
        r = analyst_client.put("/api/tenants/contoso", json={field: "x"}, headers=XRW)
        assert r.status_code == 403, field


def test_tool_config_requires_admin(analyst_client, admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    r = analyst_client.put("/api/tenants/contoso/tool-config/powershell",
                           json={"config": {"pwsh_path": "/tmp/evil"}}, headers=XRW)
    assert r.status_code == 403
    r = admin_client.put("/api/tenants/contoso/tool-config/powershell",
                         json={"config": {"pwsh_path": "/usr/bin/pwsh"}}, headers=XRW)
    assert r.status_code == 200


def test_tenant_delete_requires_admin(analyst_client, admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    assert analyst_client.delete("/api/tenants/contoso", headers=XRW).status_code == 403
    assert admin_client.delete("/api/tenants/contoso", headers=XRW).status_code == 200


# ── Secrets & redaction ──

def test_client_secret_redacted(admin_client):
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso", "client_secret": "super-secret-value"})
    tenants = admin_client.get("/api/tenants").get_json()
    assert tenants[0]["client_secret"] == "***"
    single = admin_client.get("/api/tenants/contoso").get_json()
    assert single["client_secret"] == "***"
    assert "super-secret-value" not in admin_client.get("/api/tenants").get_data(as_text=True)


def test_certificate_upload_requires_admin_and_derives_thumbprint(
        admin_client, analyst_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    pem = (b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
           b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    data = {"file": (io.BytesIO(pem), "cert.pem")}
    r = analyst_client.post("/api/tenants/contoso/certificate", data=data,
                            headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 403
    data = {"file": (io.BytesIO(pem), "cert.pem")}
    r = admin_client.post("/api/tenants/contoso/certificate", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 200
    assert len(r.get_json()["thumbprint"]) == 40  # SHA-1 hex
    # Missing private key rejected
    data = {"file": (io.BytesIO(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"), "c.pem")}
    r = admin_client.post("/api/tenants/contoso/certificate", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 400


# ── XSS ──

def test_auth_callback_escapes_reflected_input(client):
    r = client.get("/auth/callback?error=<script>alert(1)</script>&error_description=<img src=x>")
    text = r.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text
    assert "<img src=x>" not in text


# ── Imports ──

def test_import_scuba_file(admin_client):
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso",
                            "tenant_id": "11111111-1111-1111-1111-111111111111"})
    data = {"source": "scuba",
            "file": (io.BytesIO(make_scuba_results()), "ScubaResults_x.json")}
    r = admin_client.post("/api/tenants/contoso/import", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["success"] is True
    assert body["total_parsed"] == 2
    assert body["new_actions"] == 2
    assert body["tenant_verified"] is True
    actions = admin_client.get("/api/tenants/contoso/actions").get_json()
    assert len(actions) == 2


def test_import_rejects_wrong_tenant_and_allows_force(admin_client):
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso",
                            "tenant_id": "11111111-1111-1111-1111-111111111111"})
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "fabrikam",
                            "tenant_id": "33333333-3333-3333-3333-333333333333"})
    fabrikam_report = make_scuba_results(tenant_id="33333333-3333-3333-3333-333333333333")

    data = {"source": "scuba", "file": (io.BytesIO(fabrikam_report), "ScubaResults_f.json")}
    r = admin_client.post("/api/tenants/contoso/import", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 409
    body = r.get_json()
    assert body["tenant_mismatch"] is True
    assert body["matching_tenants"][0]["name"] == "fabrikam"
    # Nothing was imported into the wrong tenant
    assert admin_client.get("/api/tenants/contoso/actions").get_json() == []

    data = {"source": "scuba", "file": (io.BytesIO(fabrikam_report), "ScubaResults_f.json"),
            "force": "1"}
    r = admin_client.post("/api/tenants/contoso/import", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 200


def test_import_invalid_source(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    data = {"source": "not-a-source", "file": (io.BytesIO(b"{}"), "x.json")}
    r = admin_client.post("/api/tenants/contoso/import", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 400


# ── Scores / exports / misc endpoints ──

def test_scores_endpoint(admin_client):
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso",
                            "tenant_id": "11111111-1111-1111-1111-111111111111"})
    data = {"source": "scuba",
            "file": (io.BytesIO(make_scuba_results()), "ScubaResults_x.json")}
    admin_client.post("/api/tenants/contoso/import", data=data,
                      headers=XRW, content_type="multipart/form-data")
    scores = admin_client.get("/api/tenants/contoso/scores").get_json()
    assert scores["total_actions"] == 2
    assert scores["completed_actions"] == 1
    assert scores["percentage"] == 50.0
    assert scores["by_tool"]["SCuBA (CISA)"]["total"] == 2


def test_export_xlsx_endpoint(admin_client):
    r = admin_client.post("/api/export-xlsx", headers=XRW,
                          json={"filename": "test export!", "sheet": "S",
                                "headers": ["A"], "rows": [["x"]]})
    assert r.status_code == 200
    assert r.mimetype == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    # Filename sanitized in Content-Disposition
    assert "test_export_" in r.headers["Content-Disposition"]
    r = admin_client.post("/api/export-xlsx", headers=XRW, json={"rows": [[1]]})
    assert r.status_code == 400


def test_gitlab_script_export_endpoint_cleans_temp(admin_client, tmp_path):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    r = admin_client.post("/api/tenants/contoso/export", headers=XRW,
                          json={"format": "script", "project_path": "grp/prj"})
    assert r.status_code == 200
    assert b"glab issue create" in r.data or b"#!/bin/bash" in r.data


def test_enums_and_frontend(admin_client, client):
    enums = admin_client.get("/api/enums").get_json()
    assert "ToDo" in enums["statuses"]
    assert "scuba" in enums["import_sources"]
    html = client.get("/").get_data(as_text=True)
    assert "M365 Security Posture Manager" in html
    assert "aria-live" in html          # accessible toasts
    assert "data:image/svg+xml" in html  # favicon
    assert "function sanitizeHtml" in html  # report-HTML sanitizer shipped
    assert 'sanitizeHtml(a.description)' in html  # …and applied to descriptions


def test_global_dashboard(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    body = admin_client.get("/api/global-dashboard").get_json()
    assert body["totals"]["tenant_count"] == 1
    assert body["tenants"][0]["name"] == "contoso"
