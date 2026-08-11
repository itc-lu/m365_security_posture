"""Shared fixtures: temp database, Flask app, per-role authenticated clients."""

from __future__ import annotations

import json

import pytest

from m365_posture import webapp as webapp_module
from m365_posture.database import Database
from m365_posture.models import TenantConfig
from m365_posture.webapp import create_app

# Header required by the API's CSRF check on state-changing requests
XRW = {"X-Requested-With": "XMLHttpRequest"}

STRONG_PW = "correct-horse-battery-staple"


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "test_posture.db")


@pytest.fixture()
def db(db_path):
    return Database(db_path)


@pytest.fixture()
def app(db_path):
    application = create_app(db_path)
    application.config["TESTING"] = True
    # The login rate limiter is module-global state — isolate tests from
    # each other.
    webapp_module._login_attempts.clear()
    return application


@pytest.fixture()
def client(app):
    return app.test_client()


def _make_logged_in_client(app, db_path, username, role):
    db = Database(db_path)
    if not db.get_user_by_username(username):
        db.create_user(username=username, password=STRONG_PW, role=role,
                       display_name=username.title())
    c = app.test_client()
    r = c.post("/api/auth/login", json={"username": username, "password": STRONG_PW})
    assert r.status_code == 200, r.get_json()
    return c


@pytest.fixture()
def admin_client(app, db_path):
    return _make_logged_in_client(app, db_path, "adminuser", "admin")


@pytest.fixture()
def analyst_client(app, db_path):
    return _make_logged_in_client(app, db_path, "analystuser", "analyst")


@pytest.fixture()
def viewer_client(app, db_path):
    return _make_logged_in_client(app, db_path, "vieweruser", "viewer")


@pytest.fixture()
def tenant(db):
    """A tenant named 'contoso' with an Entra tenant id."""
    db.create_tenant("contoso", TenantConfig(
        tenant_id="11111111-1111-1111-1111-111111111111",
        tenant_name="contoso", display_name="Contoso Ltd"))
    return db.get_tenant("contoso")


def make_scuba_results(tenant_id="11111111-1111-1111-1111-111111111111",
                       controls=None) -> bytes:
    """Minimal rich ScubaResults JSON accepted by ScubaParser."""
    if controls is None:
        controls = [
            {"Control ID": "MS.AAD.1.1v1",
             "Requirement": "Legacy authentication SHALL be blocked",
             "Result": "Fail", "Criticality": "Shall",
             "Details": "1 conditional access policy(s) found"},
            {"Control ID": "MS.AAD.3.2v1",
             "Requirement": "MFA SHALL be required for all users",
             "Result": "Pass", "Criticality": "Shall", "Details": "ok"},
        ]
    doc = {
        "MetaData": {
            "TenantId": tenant_id,
            "DisplayName": "Contoso Ltd",
            "DomainName": "contoso.onmicrosoft.com",
            "ProductSuite": "M365",
            "ProductsAssessed": ["AAD"],
            "Tool": "ScubaGear",
            "ToolVersion": "1.6.0",
            "TimestampZulu": "2026-08-01T00:00:00Z",
            "ReportUUID": "uuid-1",
        },
        "Summary": {"AAD": {"Passes": 1, "Failures": 1}},
        "Results": {"AAD": [{
            "GroupName": "Legacy Authentication",
            "GroupNumber": "1",
            "GroupReferenceURL": "https://example.test/aad1",
            "Controls": controls,
        }]},
        "AnnotatedFailedPolicies": {},
    }
    return json.dumps(doc).encode()
