"""Tests for structured risk-acceptance reasons and the analysis reporting."""

from __future__ import annotations

import pytest

from .conftest import STRONG_PW, XRW


def _accept(db, tenant, title, reason_id=None, priority="High", max_score=5.0,
            **extra):
    a = db.create_action(tenant, {"title": title, "priority": priority,
                                  "risk_level": "High", "score": 0.0,
                                  "max_score": max_score,
                                  "implementation_effort": "Low",
                                  "user_impact": "Low", **extra})
    db.accept_risk(a["id"], "justified", "CISO", reason_id=reason_id)
    return a


def _reason_by_name(db, name):
    return next(r for r in db.list_risk_reasons() if r["name"] == name)


# ── Catalog ──

def test_default_reason_catalog_seeded(db):
    reasons = db.list_risk_reasons()
    names = {r["name"] for r in reasons}
    assert "Entra ID P2 licence required" in names
    assert "Defender for Office 365 licence required" in names
    assert "No staff capacity available" in names
    assert "Skills or training missing" in names
    categories = {r["category"] for r in reasons}
    assert {"Licensing", "Budget", "Resources", "Skills"} <= categories


def test_reason_crud_and_unique_name(db):
    r = db.create_risk_reason("Custom blocker", "Technical", "desc")
    assert r["name"] == "Custom blocker" and r["is_active"] is True
    with pytest.raises(ValueError, match="already exists"):
        db.create_risk_reason("Custom blocker", "Other")
    updated = db.update_risk_reason(r["id"], name="Renamed blocker",
                                    category="Business")
    assert updated["name"] == "Renamed blocker"
    assert db.delete_risk_reason(r["id"]) == {"deleted": True, "deactivated": False}
    assert db.get_risk_reason(r["id"]) is None


def test_delete_used_reason_deactivates(db, tenant):
    reason = _reason_by_name(db, "Entra ID P2 licence required")
    _accept(db, "contoso", "PIM rollout", reason["id"])
    result = db.delete_risk_reason(reason["id"])
    assert result["deactivated"] is True
    stored = db.get_risk_reason(reason["id"])
    assert stored["is_active"] is False
    # Historical acceptances keep their label
    action = db.get_actions("contoso", {"status": "Risk Accepted"})[0]
    assert action["risk_reason_name"] == "Entra ID P2 licence required"
    # Inactive reasons disappear from the default (selectable) list
    assert reason["id"] not in {r["id"] for r in db.list_risk_reasons()}
    assert reason["id"] in {r["id"] for r in db.list_risk_reasons(include_inactive=True)}


# ── Acceptance workflow ──

def test_accept_risk_stores_reason_and_history(db, tenant):
    reason = _reason_by_name(db, "Defender for Office 365 licence required")
    a = _accept(db, "contoso", "Safe Links", reason["id"])
    stored = db.get_action(a["id"])
    assert stored["risk_reason_id"] == reason["id"]
    assert stored["risk_reason_name"] == reason["name"]
    assert stored["risk_reason_category"] == "Licensing"
    assert any(reason["name"] in (h.get("notes") or "")
               for h in stored["history"])


def test_accept_risk_unknown_reason_rejected(db, tenant):
    a = db.create_action("contoso", {"title": "X"})
    with pytest.raises(ValueError, match="Unknown risk reason"):
        db.accept_risk(a["id"], "j", "o", reason_id="nope")


def test_usage_counts_in_catalog(db, tenant):
    reason = _reason_by_name(db, "Budget not approved")
    _accept(db, "contoso", "A", reason["id"])
    _accept(db, "contoso", "B", reason["id"])
    entry = _reason_by_name(db, "Budget not approved")
    assert entry["active_usage"] == 2
    assert entry["total_usage"] == 2


# ── Analysis ──

def test_risk_analysis_grouping(db, tenant):
    lic = _reason_by_name(db, "Defender for Office 365 licence required")
    staff = _reason_by_name(db, "No staff capacity available")
    _accept(db, "contoso", "Safe Links", lic["id"], priority="Critical",
            max_score=8.0, workload="Exchange Online")
    _accept(db, "contoso", "Safe Attachments", lic["id"], priority="High",
            max_score=6.0, workload="Exchange Online")
    _accept(db, "contoso", "CA cleanup", staff["id"], priority="Medium",
            max_score=2.0, workload="Entra ID")
    _accept(db, "contoso", "Orphan", None, priority="Low", max_score=1.0)
    # An open action so total_max > accepted potential
    db.create_action("contoso", {"title": "Open", "score": 0.0, "max_score": 3.0})

    analysis = db.get_risk_analysis("contoso")
    assert analysis["total_accepted"] == 4
    assert analysis["assigned"] == 3
    assert analysis["unassigned"]["count"] == 1
    assert analysis["unassigned"]["score_potential"] == 1.0

    top = analysis["by_reason"][0]  # sorted by score potential
    assert top["name"] == "Defender for Office 365 licence required"
    assert top["count"] == 2
    assert top["by_priority"] == {"Critical": 1, "High": 1}
    assert top["score_potential"] == 14.0
    assert top["workloads"] == {"Exchange Online": 2}
    assert top["score_potential_pct"] > 0
    assert len(top["actions"]) == 2
    assert all(a["roi"] > 0 for a in top["actions"])

    cats = {c["category"]: c for c in analysis["by_category"]}
    assert cats["Licensing"]["count"] == 2
    assert cats["Licensing"]["critical_high"] == 2
    assert cats["Resources"]["count"] == 1
    assert analysis["total_score_potential"] == 17.0


def test_risk_analysis_empty_tenant(db, tenant):
    analysis = db.get_risk_analysis("contoso")
    assert analysis["total_accepted"] == 0
    assert analysis["by_reason"] == []
    assert analysis["unassigned"]["count"] == 0


# ── API surface ──

def test_reason_endpoints_rbac(admin_client, analyst_client, viewer_client):
    # Everyone logged-in can read the catalog (needed to accept risks)
    assert analyst_client.get("/api/risk-reasons").status_code == 200
    assert viewer_client.get("/api/risk-reasons").status_code == 200
    # Only admins manage it
    r = analyst_client.post("/api/risk-reasons", headers=XRW,
                            json={"name": "X", "category": "Other"})
    assert r.status_code == 403
    r = admin_client.post("/api/risk-reasons", headers=XRW,
                          json={"name": "Copilot licence required",
                                "category": "Licensing"})
    assert r.status_code == 201
    rid = r.get_json()["id"]
    assert analyst_client.put(f"/api/risk-reasons/{rid}", headers=XRW,
                              json={"name": "Y"}).status_code == 403
    assert analyst_client.delete(f"/api/risk-reasons/{rid}",
                                 headers=XRW).status_code == 403
    assert admin_client.delete(f"/api/risk-reasons/{rid}",
                               headers=XRW).status_code == 200


def test_reason_endpoint_validation(admin_client):
    r = admin_client.post("/api/risk-reasons", headers=XRW,
                          json={"name": "", "category": "Licensing"})
    assert r.status_code == 400
    r = admin_client.post("/api/risk-reasons", headers=XRW,
                          json={"name": "Z", "category": "NotACategory"})
    assert r.status_code == 400
    r = admin_client.post("/api/risk-reasons", headers=XRW,
                          json={"name": "Entra ID P2 licence required",
                                "category": "Licensing"})
    assert r.status_code == 400  # duplicate of seeded reason


def test_accept_risk_api_with_reason(admin_client, db_path):
    from m365_posture.database import Database
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    a = admin_client.post("/api/tenants/contoso/actions", headers=XRW,
                          json={"title": "Ctl", "max_score": 4.0}).get_json()
    db = Database(db_path)
    reason = _reason_by_name(db, "Intune licence required")
    r = admin_client.post(f"/api/actions/{a['id']}/accept-risk", headers=XRW,
                          json={"justification": "j", "risk_owner": "o",
                                "reason_id": reason["id"]})
    assert r.status_code == 200
    assert r.get_json()["risk_reason_name"] == "Intune licence required"
    # Unknown reason rejected cleanly
    b = admin_client.post("/api/tenants/contoso/actions", headers=XRW,
                          json={"title": "Ctl2"}).get_json()
    r = admin_client.post(f"/api/actions/{b['id']}/accept-risk", headers=XRW,
                          json={"justification": "j", "risk_owner": "o",
                                "reason_id": "bogus"})
    assert r.status_code == 400
    # update_action validates reason ids as well
    r = admin_client.put(f"/api/actions/{a['id']}", headers=XRW,
                         json={"risk_reason_id": "bogus"})
    assert r.status_code == 400
    r = admin_client.put(f"/api/actions/{a['id']}", headers=XRW,
                         json={"risk_reason_id": None})
    assert r.status_code == 200


def test_risk_analysis_endpoints(admin_client, db_path):
    from m365_posture.database import Database
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    admin_client.post("/api/tenants", json={"name": "fabrikam"}, headers=XRW)
    db = Database(db_path)
    lic = _reason_by_name(db, "Entra ID P2 licence required")
    _accept(db, "contoso", "PIM", lic["id"], priority="Critical", max_score=9.0)
    _accept(db, "fabrikam", "PIM", lic["id"], priority="High", max_score=9.0)

    r = admin_client.get("/api/tenants/contoso/risk-analysis")
    assert r.status_code == 200
    body = r.get_json()
    assert body["total_accepted"] == 1
    assert body["by_reason"][0]["name"] == "Entra ID P2 licence required"

    r = admin_client.get("/api/control-plane/risk-analysis")
    assert r.status_code == 200
    rollup = r.get_json()
    assert rollup["totals"]["total_accepted"] == 2
    entry = next(x for x in rollup["reasons"]
                 if x["name"] == "Entra ID P2 licence required")
    assert entry["count"] == 2
    assert entry["critical_high"] == 2
    assert set(entry["by_tenant"].keys()) == {"contoso", "fabrikam"}
    assert entry["score_potential"] == 18.0


def test_enums_expose_reason_categories(admin_client):
    enums = admin_client.get("/api/enums").get_json()
    assert "Licensing" in enums["risk_reason_categories"]
    assert "Skills" in enums["risk_reason_categories"]


def test_frontend_ships_reason_ui(client):
    html = client.get("/").get_data(as_text=True)
    assert "Analysis by Reason" in html
    assert "showManageReasons" in html
    assert "riskReasonSelectHtml" in html
