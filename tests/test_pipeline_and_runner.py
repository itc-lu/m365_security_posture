"""Import pipeline end-to-end tests plus runner/planner-on-db helpers."""

from __future__ import annotations

import pytest

from m365_posture.drift import detect_drift
from m365_posture.import_pipeline import TenantMismatchError, process_file_import
from m365_posture.models import TenantConfig
from m365_posture.planner import get_prioritized_actions, simulate_plan, suggest_phases
from m365_posture.runner import _config_timeout, _module_import_prefix, _ps_quote, find_pwsh

from .conftest import make_scuba_results


def _write_report(tmp_path, name="ScubaResults_x.json", **kw):
    p = tmp_path / name
    p.write_bytes(make_scuba_results(**kw))
    return str(p)


def test_process_file_import_full_pipeline(db, tenant, tmp_path):
    path = _write_report(tmp_path)
    result = process_file_import(db, "contoso", "scuba", path, "ScubaResults_x.json")
    assert result["success"] is True
    assert result["new_actions"] == 2
    assert result["tenant_verified"] is True
    assert result["snapshot"]["id"]
    # SCuBA import stores a report record
    assert result["scuba_report_id"]
    reports = db.get_scuba_reports("contoso")
    assert reports[0]["total_controls"] == 2
    # Post-processing ran: correlation groups exist, E8 mapping applied to MFA
    actions = db.get_actions("contoso")
    mfa = next(a for a in actions if "MFA" in a["title"])
    assert mfa["essential_eight_control"] == "Multi-Factor Authentication"


def test_pipeline_rejects_wrong_tenant(db, tmp_path):
    db2 = db
    db2.create_tenant("contoso", TenantConfig(
        tenant_id="11111111-1111-1111-1111-111111111111", tenant_name="contoso"))
    db2.create_tenant("fabrikam", TenantConfig(
        tenant_id="33333333-3333-3333-3333-333333333333", tenant_name="fabrikam"))
    path = _write_report(tmp_path, tenant_id="33333333-3333-3333-3333-333333333333")
    with pytest.raises(TenantMismatchError) as exc:
        process_file_import(db2, "contoso", "scuba", path, "r.json")
    payload = exc.value.payload
    assert payload["tenant_mismatch"] is True
    assert payload["matching_tenants"][0]["name"] == "fabrikam"
    # Forcing bypasses the guard
    result = process_file_import(db2, "contoso", "scuba", path, "r.json",
                                 force_tenant=True)
    assert result["success"] is True


def test_stale_action_detection(db, tenant, tmp_path):
    process_file_import(db, "contoso", "scuba",
                        _write_report(tmp_path, "r1.json"), "r1.json")
    # Second import contains only ONE of the two controls
    only_one = [{"Control ID": "MS.AAD.1.1v1",
                 "Requirement": "Legacy authentication SHALL be blocked",
                 "Result": "Pass", "Criticality": "Shall", "Details": "fixed"}]
    result = process_file_import(
        db, "contoso", "scuba",
        _write_report(tmp_path, "r2.json", controls=only_one), "r2.json")
    stale_ids = {s["title"] for s in result["stale_actions"]}
    assert any("MFA" in t for t in stale_ids)
    assert len(result["stale_actions"]) == 1


def test_drift_detection_between_imports(db, tenant, tmp_path):
    process_file_import(db, "contoso", "scuba",
                        _write_report(tmp_path, "r1.json"), "r1.json")
    # Second import: the failing control now passes → improvement
    fixed = [
        {"Control ID": "MS.AAD.1.1v1",
         "Requirement": "Legacy authentication SHALL be blocked",
         "Result": "Pass", "Criticality": "Shall", "Details": "fixed"},
        {"Control ID": "MS.AAD.3.2v1",
         "Requirement": "MFA SHALL be required for all users",
         "Result": "Pass", "Criticality": "Shall", "Details": "ok"},
    ]
    result = process_file_import(
        db, "contoso", "scuba",
        _write_report(tmp_path, "r2.json", controls=fixed), "r2.json")
    drift = result["drift"]
    assert drift["score_delta"] > 0
    assert drift["has_drift"] is True
    assert any(i["scope"] == "SCuBA (CISA)" for i in drift["improvements"])
    assert db.get_drift_reports("contoso")


def test_drift_needs_two_snapshots(db, tenant):
    drift = detect_drift(db, "contoso")
    assert drift["has_drift"] is False
    assert "Not enough snapshots" in drift["summary"]


# ── Planner on a real DB ──

def _seed_plan_actions(db):
    ids = []
    specs = [
        ("Free quick win", "", "Low", "High", 10.0),
        ("Premium hard control", "Entra ID P2", "High", "Medium", 8.0),
        ("Standard control", "E3", "Medium", "Medium", 5.0),
    ]
    for title, lic, effort, prio, max_score in specs:
        a = db.create_action("contoso", {
            "title": title, "required_licence": lic,
            "implementation_effort": effort, "priority": prio,
            "risk_level": "High", "user_impact": "Low",
            "score": 0.0, "max_score": max_score,
        })
        ids.append(a["id"])
    return ids


def test_simulate_plan_projects_gains(db, tenant):
    ids = _seed_plan_actions(db)
    sim = simulate_plan(db, "contoso", ids)
    assert sim["actions_count"] == 3
    assert sim["projected_score_gain"] == 23.0
    assert sim["projected_percentage"] == 100.0
    assert "Entra ID P2" in sim["licences_needed"]


def test_simulate_plan_all_completed(db, tenant):
    a = db.create_action("contoso", {"title": "Done", "status": "Completed"})
    assert "error" in simulate_plan(db, "contoso", [a["id"]])


def test_suggest_phases_orders_by_licence_tier(db, tenant):
    ids = _seed_plan_actions(db)
    phases = suggest_phases(db, "contoso", ids, num_phases=3)
    assert len(phases) == 3
    assert phases[0]["name"].endswith("Quick Wins")
    # Free/included actions land in phase 1 before licensed ones
    assert phases[0]["actions"][0]["title"] == "Free quick win"
    all_titles = [a["title"] for ph in phases for a in ph["actions"]]
    assert len(all_titles) == 3


def test_prioritized_actions_excludes_finished(db, tenant):
    _seed_plan_actions(db)
    done = db.create_action("contoso", {"title": "Finished", "status": "Completed"})
    top = get_prioritized_actions(db, "contoso")
    assert done["id"] not in [a["id"] for a in top]
    assert all("roi_score" in a for a in top)


# ── Runner helpers ──

def test_ps_quote_escapes_single_quotes():
    assert _ps_quote("plain") == "'plain'"
    assert _ps_quote("O'Brien") == "'O''Brien'"
    assert _ps_quote("a'; Remove-Item x; '") == "'a''; Remove-Item x; '''"


def test_config_timeout_tolerates_garbage():
    assert _config_timeout({}) == 3600
    assert _config_timeout({"timeout": 120}) == 120
    assert _config_timeout({"timeout": "180"}) == 180
    assert _config_timeout({"timeout": "soon"}) == 3600
    assert _config_timeout({"timeout": -5}) == 3600


def test_module_import_prefix(tmp_path):
    assert _module_import_prefix("", "ScubaGear") == ""
    mod = tmp_path / "ScubaGear"
    mod.mkdir()
    (mod / "ScubaGear.psd1").write_text("@{}")
    prefix = _module_import_prefix(str(tmp_path), "ScubaGear")
    assert prefix.startswith("Import-Module '")
    assert "ScubaGear" in prefix
    with pytest.raises(RuntimeError, match="No ZeroTrustAssessment module"):
        _module_import_prefix(str(tmp_path), "ZeroTrustAssessment")


def test_find_pwsh_with_bad_override():
    assert find_pwsh({"pwsh_path": "/nonexistent/pwsh"}) is None
