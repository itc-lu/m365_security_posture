"""Tests for per-tenant workload exclusions: excluded workloads disappear
from lists, scores, dashboards, exports, compliance and analyses while
imports keep updating them in the background."""

from __future__ import annotations

from m365_posture.database import Database
from m365_posture.models import Action, ActionStatus

from .conftest import XRW


def _seed(db, tenant="contoso"):
    db.create_action(tenant, {"title": "Entra control", "workload": "Entra ID",
                              "score": 0.0, "max_score": 10.0})
    db.create_action(tenant, {"title": "Exchange control", "workload": "Exchange Online",
                              "score": 0.0, "max_score": 10.0})
    db.create_action(tenant, {"title": "Defender control", "workload": "Defender",
                              "score": 10.0, "max_score": 10.0,
                              "status": ActionStatus.COMPLETED.value})


def test_get_actions_hides_excluded_workloads(db, tenant):
    _seed(db)
    assert len(db.get_actions("contoso")) == 3
    db.update_tenant("contoso", excluded_workloads=["Exchange Online", "Defender"])
    assert db.get_excluded_workloads("contoso") == ["Exchange Online", "Defender"]

    visible = db.get_actions("contoso")
    assert [a["title"] for a in visible] == ["Entra control"]
    # Escape hatch for data hygiene / internal jobs
    assert len(db.get_actions("contoso", include_excluded=True)) == 3
    # Explicitly filtering for an excluded workload stays empty
    assert db.get_actions("contoso", {"workload": "Exchange Online"}) == []


def test_scores_ignore_excluded_workloads(db, tenant):
    _seed(db)
    full = db.get_scores("contoso")
    assert full["total_actions"] == 3
    assert "Defender" in full["by_workload"]

    db.update_tenant("contoso", excluded_workloads=["Defender", "Exchange Online"])
    scores = db.get_scores("contoso")
    assert scores["total_actions"] == 1
    assert set(scores["by_workload"].keys()) == {"Entra ID"}
    assert scores["total_max"] == 10.0
    # The completed Defender points no longer inflate the percentage
    assert scores["percentage"] == 0.0


def test_blocked_actions_and_risk_analysis_respect_exclusions(db, tenant):
    _seed(db)
    actions = {a["title"]: a for a in db.get_actions("contoso")}
    db.add_dependency(actions["Exchange control"]["id"], actions["Entra control"]["id"])
    db.accept_risk(actions["Exchange control"]["id"], "j", "o")

    db.update_tenant("contoso", excluded_workloads=["Exchange Online"])
    assert db.get_blocked_actions("contoso") == []
    analysis = db.get_risk_analysis("contoso")
    assert analysis["total_accepted"] == 0


def test_compliance_summary_respects_exclusions(db, tenant):
    a = db.create_action("contoso", {"title": "Require MFA for admins",
                                     "workload": "Entra ID"})
    b = db.create_action("contoso", {"title": "Enable DKIM signing",
                                     "workload": "Exchange Online"})
    for action_id in (a["id"], b["id"]):
        db.bulk_add_compliance_mappings([{
            "action_id": action_id, "framework": "CIS Microsoft 365",
            "control_id": "1.1", "control_name": "MFA", "control_family": "Auth"}])
    before = db.get_compliance_summary("contoso")
    assert len(before["CIS Microsoft 365"]["families"]["Auth"]["controls"]["1.1"]["actions"]) == 2

    db.update_tenant("contoso", excluded_workloads=["Exchange Online"])
    after = db.get_compliance_summary("contoso")
    ctrl = after["CIS Microsoft 365"]["families"]["Auth"]["controls"]["1.1"]
    assert len(ctrl["actions"]) == 1
    assert ctrl["actions"][0]["title"] == "Require MFA for admins"


def test_imports_still_update_hidden_workloads(db, tenant):
    db.update_tenant("contoso", excluded_workloads=["Exchange Online"])
    action = Action(title="EXO control", workload="Exchange Online",
                    source_tool="SCuBA (CISA)", source_id="scuba_exo1",
                    score=0.0, max_score=1.0)
    new, updated, _, _ = db.merge_actions("contoso", [action], "SCuBA (CISA)", "r1")
    assert new == 1
    assert db.get_actions("contoso") == []  # hidden
    # Re-import updates the hidden action rather than duplicating it
    again = Action(title="EXO control", workload="Exchange Online",
                   source_tool="SCuBA (CISA)", source_id="scuba_exo1",
                   score=1.0, max_score=1.0, status=ActionStatus.COMPLETED.value)
    new, updated, _, ids = db.merge_actions("contoso", [again], "SCuBA (CISA)", "r2")
    assert (new, updated) == (0, 1)
    # Re-including the workload brings the current state straight back
    db.update_tenant("contoso", excluded_workloads=[])
    restored = db.get_actions("contoso")
    assert restored[0]["status"] == ActionStatus.COMPLETED.value


# ── API surface ──

def test_exclusion_api_validation_and_effect(admin_client, analyst_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    admin_client.post("/api/tenants/contoso/actions", headers=XRW,
                      json={"title": "EXO", "workload": "Exchange Online",
                            "max_score": 5.0})
    admin_client.post("/api/tenants/contoso/actions", headers=XRW,
                      json={"title": "Entra", "workload": "Entra ID",
                            "max_score": 5.0})

    # Invalid values rejected
    r = admin_client.put("/api/tenants/contoso", headers=XRW,
                         json={"excluded_workloads": "Exchange Online"})
    assert r.status_code == 400
    r = admin_client.put("/api/tenants/contoso", headers=XRW,
                         json={"excluded_workloads": ["Notes"]})
    assert r.status_code == 400
    assert "Unknown workload" in r.get_json()["error"]

    # Analysts may manage exclusions (display scoping, not credentials)
    r = analyst_client.put("/api/tenants/contoso", headers=XRW,
                           json={"excluded_workloads": ["Exchange Online"]})
    assert r.status_code == 200

    actions = admin_client.get("/api/tenants/contoso/actions").get_json()
    assert [a["title"] for a in actions] == ["Entra"]
    scores = admin_client.get("/api/tenants/contoso/scores").get_json()
    assert scores["total_actions"] == 1
    dash = admin_client.get("/api/global-dashboard").get_json()
    assert dash["tenants"][0]["total_actions"] == 1

    # Exports follow the same visibility
    csv_export = admin_client.get(
        "/api/tenants/contoso/export-actions?format=csv").get_data(as_text=True)
    assert "Entra" in csv_export and "EXO" not in csv_export

    # Clearing restores everything
    admin_client.put("/api/tenants/contoso", headers=XRW,
                     json={"excluded_workloads": []})
    assert len(admin_client.get("/api/tenants/contoso/actions").get_json()) == 2


def test_cross_tenant_view_respects_exclusions(admin_client, db_path):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    admin_client.post("/api/tenants", json={"name": "fabrikam"}, headers=XRW)
    db = Database(db_path)
    for tenant in ("contoso", "fabrikam"):
        a = db.create_action(tenant, {"title": "Enable DKIM", "workload": "Exchange Online",
                                      "source_tool": "SCuBA (CISA)", "source_id": "scuba_dkim"})
        db.create_global_action_from_tenant_action(a["id"])
    db.update_tenant("contoso", excluded_workloads=["Exchange Online"])

    body = admin_client.get("/api/control-plane/cross-tenant").get_json()
    ga = next(g for g in body["global_actions"] if g["title"] == "Enable DKIM")
    assert "fabrikam" in ga["tenant_status"]
    assert "contoso" not in ga["tenant_status"]  # excluded there


def test_frontend_ships_exclusion_ui(client):
    html = client.get("/").get_data(as_text=True)
    assert "excludedWorkloadsNotice" in html
    assert "Excluded Workloads" in html
    assert "cpt-excl-wl" in html
