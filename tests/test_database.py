"""Database layer tests: merge semantics, status protection, dedup,
risk acceptance lifecycle, scoring, users."""

from __future__ import annotations

from datetime import datetime, timedelta

from m365_posture.models import Action, ActionStatus, TenantConfig


def _mk_action(**kw):
    defaults = dict(source_tool="SCuBA (CISA)", max_score=1.0, score=0.0,
                    status=ActionStatus.TODO.value)
    defaults.update(kw)
    return Action(**defaults)


def test_tenant_crud(db):
    db.create_tenant("t1", TenantConfig(tenant_name="t1", display_name="T One"))
    assert db.get_tenant("t1")["display_name"] == "T One"
    assert db.get_tenant("t1")["is_active"] == 1  # first tenant becomes active
    db.update_tenant("t1", notes="hello")
    assert db.get_tenant("t1")["notes"] == "hello"
    db.delete_tenant("t1")
    assert db.get_tenant("t1") is None


def test_merge_inserts_then_updates(db, tenant):
    a = _mk_action(title="Block legacy auth", source_id="scuba_MS.AAD.1.1v1")
    new, updated, details, ids = db.merge_actions("contoso", [a], "SCuBA (CISA)", "r1.json")
    assert (new, updated) == (1, 0)

    a2 = _mk_action(title="Block legacy auth", source_id="scuba_MS.AAD.1.1v1",
                    status=ActionStatus.COMPLETED.value, score=1.0)
    new, updated, details, ids = db.merge_actions("contoso", [a2], "SCuBA (CISA)", "r2.json")
    assert (new, updated) == (0, 1)
    stored = db.get_action(ids[0])
    assert stored["status"] == ActionStatus.COMPLETED.value
    assert stored["score"] == 1.0
    # A status change through an import is recorded in history
    assert any(h["new_status"] == "Completed" for h in stored["history"])


def test_merge_protects_manual_status_and_records_conflict(db, tenant):
    a = _mk_action(title="Require MFA", source_id="scuba_MS.AAD.3.2v1")
    _, _, _, ids = db.merge_actions("contoso", [a], "SCuBA (CISA)", "r1.json")
    aid = ids[0]

    # User completes the action manually
    db.update_action(aid, {"status": ActionStatus.COMPLETED.value}, changed_by="alice")

    # A later import still reports failure → status must NOT be overwritten
    again = _mk_action(title="Require MFA", source_id="scuba_MS.AAD.3.2v1")
    _, _, details, _ = db.merge_actions("contoso", [again], "SCuBA (CISA)", "r2.json")
    stored = db.get_action(aid)
    assert stored["status"] == ActionStatus.COMPLETED.value
    assert stored["import_suggested_status"] == ActionStatus.TODO.value
    assert details[0].get("status_protected") is True
    # The completed state also keeps the score pinned at max
    assert stored["score"] == stored["max_score"]

    conflicts = db.get_import_status_conflicts("contoso")
    assert [c["id"] for c in conflicts] == [aid]

    # keep_mine clears the conflict without touching the status
    db.resolve_import_status_conflicts("contoso", "keep_mine", [aid], "alice")
    assert db.get_import_status_conflicts("contoso") == []
    assert db.get_action(aid)["status"] == ActionStatus.COMPLETED.value


def test_conflict_use_import_applies_status(db, tenant):
    a = _mk_action(title="Require MFA", source_id="s1")
    _, _, _, ids = db.merge_actions("contoso", [a], "SCuBA (CISA)", "r1.json")
    aid = ids[0]
    db.update_action(aid, {"status": ActionStatus.RISK_ACCEPTED.value})
    again = _mk_action(title="Require MFA", source_id="s1",
                       status=ActionStatus.COMPLETED.value, score=1.0)
    db.merge_actions("contoso", [again], "SCuBA (CISA)", "r2.json")
    assert db.get_import_status_conflicts("contoso")  # conflict present
    db.resolve_import_status_conflicts("contoso", "use_import", None, "bob")
    stored = db.get_action(aid)
    assert stored["status"] == ActionStatus.COMPLETED.value
    assert stored["import_suggested_status"] == ""


def test_conflict_clears_when_import_agrees_again(db, tenant):
    a = _mk_action(title="X", source_id="s2")
    _, _, _, ids = db.merge_actions("contoso", [a], "SCuBA (CISA)", "r1.json")
    aid = ids[0]
    db.update_action(aid, {"status": ActionStatus.COMPLETED.value})
    db.merge_actions("contoso", [_mk_action(title="X", source_id="s2")],
                     "SCuBA (CISA)", "r2.json")
    assert db.get_import_status_conflicts("contoso")
    # Now the tool also reports Completed → conflict auto-clears
    db.merge_actions("contoso",
                     [_mk_action(title="X", source_id="s2",
                                 status=ActionStatus.COMPLETED.value, score=1.0)],
                     "SCuBA (CISA)", "r3.json")
    assert db.get_import_status_conflicts("contoso") == []


def test_merge_does_not_wipe_max_score_with_zero(db, tenant):
    """Graph imports without control profiles report max_score 0 — that must
    not destroy previously known values (regression test)."""
    a = _mk_action(title="Admin MFA", source_id="AdminMFAV2",
                   source_tool="Microsoft Secure Score", score=2.0, max_score=10.0)
    _, _, _, ids = db.merge_actions("contoso", [a], "Microsoft Secure Score", "r1.json")
    aid = ids[0]

    profileless = _mk_action(title="Admin MFA", source_id="AdminMFAV2",
                             source_tool="Microsoft Secure Score",
                             score=2.0, max_score=0.0)
    db.merge_actions("contoso", [profileless], "Microsoft Secure Score", "r2.json")
    stored = db.get_action(aid)
    assert stored["max_score"] == 10.0
    assert stored["score_percentage"] == 20.0

    # But an explicit Not Applicable with 0/0 (Zero Trust semantics) is honoured
    na = _mk_action(title="Admin MFA", source_id="AdminMFAV2",
                    source_tool="Microsoft Secure Score",
                    score=0.0, max_score=0.0,
                    status=ActionStatus.NOT_APPLICABLE.value)
    db.merge_actions("contoso", [na], "Microsoft Secure Score", "r3.json")
    assert db.get_action(aid)["max_score"] == 0.0


def test_completed_transition_autofills_score(db, tenant):
    a = _mk_action(title="Pass/fail control", source_id="pf1")
    _, _, _, ids = db.merge_actions("contoso", [a], "SCuBA (CISA)", "r1.json")
    aid = ids[0]
    db.update_action(aid, {"status": ActionStatus.COMPLETED.value})
    stored = db.get_action(aid)
    assert stored["score"] == stored["max_score"] == 1.0
    assert stored["score_percentage"] == 100.0


def test_deduplicate_keeps_actions_without_source_id(db, tenant):
    """Manual actions share an empty source_id; dedup must never collapse
    them into one (regression test)."""
    db.create_action("contoso", {"title": "Manual A", "source_tool": "Manual"})
    db.create_action("contoso", {"title": "Manual B", "source_tool": "Manual"})
    result = db.deduplicate_actions("contoso")
    assert result["removed"] == 0
    assert len(db.get_actions("contoso")) == 2


def test_deduplicate_merges_old_style_secure_score_ids(db, tenant):
    db.create_action("contoso", {"title": "Old", "source_tool": "Microsoft Secure Score",
                                 "source_id": "ss_adminmfav2"})
    db.create_action("contoso", {"title": "New", "source_tool": "Microsoft Secure Score",
                                 "source_id": "AdminMFAV2"})
    result = db.deduplicate_actions("contoso", "Microsoft Secure Score")
    assert result["removed"] == 1


def test_risk_acceptance_lifecycle(db, tenant):
    a = db.create_action("contoso", {"title": "Risky control", "max_score": 1.0})
    expired_date = (datetime.utcnow() - timedelta(days=1)).isoformat()
    db.accept_risk(a["id"], "Business exception", "CISO",
                   expiry_date=expired_date, changed_by="alice")
    stored = db.get_action(a["id"])
    assert stored["status"] == ActionStatus.RISK_ACCEPTED.value
    assert stored["risk_owner"] == "CISO"

    expired = db.expire_risk_acceptances("contoso")
    assert [e["id"] for e in expired] == [a["id"]]
    assert db.get_action(a["id"])["status"] == ActionStatus.TODO.value
    # History documents the expiry
    assert any("expired" in (h.get("notes") or "") for h in db.get_action(a["id"])["history"])


def test_get_scores_graph_override_and_adjusted(db, tenant):
    actions = [
        _mk_action(title="A", source_id="a", source_tool="Microsoft Secure Score",
                   score=10.0, max_score=10.0, status=ActionStatus.COMPLETED.value),
        _mk_action(title="B", source_id="b", source_tool="Microsoft Secure Score",
                   score=0.0, max_score=10.0),
        _mk_action(title="C", source_id="c", source_tool="Microsoft Secure Score",
                   score=0.0, max_score=10.0, status=ActionStatus.RISK_ACCEPTED.value),
    ]
    db.merge_actions("contoso", actions, "Microsoft Secure Score", "r.json")
    db.store_graph_scores("contoso", {"currentScore": 45.0, "maxScore": 60.0})

    full = db.get_scores("contoso")
    # Graph totals are authoritative for the full view: 45/60 = 75%
    assert full["by_tool"]["Microsoft Secure Score"]["percentage"] == 75.0

    adjusted = db.get_scores("contoso", exclude_ra=True)
    # With exclusions the Graph totals (which include everything) must NOT be
    # substituted — the per-action sum 10/20 = 50% applies.
    assert adjusted["by_tool"]["Microsoft Secure Score"]["percentage"] == 50.0
    assert adjusted["excluded_count"] == 1


def test_score_snapshot_and_trend(db, tenant):
    db.merge_actions("contoso", [_mk_action(title="A", source_id="a")],
                     "SCuBA (CISA)", "r.json")
    snap = db.take_score_snapshot("contoso", trigger="test")
    assert snap["id"]
    snaps = db.get_score_snapshots("contoso")
    assert len(snaps) == 1
    assert snaps[0]["trigger"] == "test"
    assert "adj_percentage" in snaps[0]


def test_dependencies_and_blocked_actions(db, tenant):
    a = db.create_action("contoso", {"title": "Deploy CA policy"})
    b = db.create_action("contoso", {"title": "Buy P1 licences"})
    db.add_dependency(a["id"], b["id"])
    blocked = db.get_blocked_actions("contoso")
    assert len(blocked) == 1
    assert blocked[0]["id"] == a["id"]
    assert blocked[0]["blocked_by"][0]["id"] == b["id"]
    # Completing the dependency unblocks
    db.update_action(b["id"], {"status": ActionStatus.COMPLETED.value})
    assert db.get_blocked_actions("contoso") == []


def test_dependency_cycle_rejected(db, tenant):
    import pytest
    a = db.create_action("contoso", {"title": "A"})
    b = db.create_action("contoso", {"title": "B"})
    db.add_dependency(a["id"], b["id"])
    with pytest.raises(ValueError):
        db.add_dependency(b["id"], a["id"])
    with pytest.raises(ValueError):
        db.add_dependency(a["id"], a["id"])


def test_user_management_and_auth(db):
    u = db.create_user("alice", "a-long-secure-password", role="analyst")
    assert db.authenticate_user("alice", "a-long-secure-password")["id"] == u["id"]
    assert db.authenticate_user("alice", "wrong") is None
    assert db.authenticate_user("ghost", "x") is None
    # password_hash never leaks through the public accessors
    assert "password_hash" not in db.get_user(u["id"])
    db.update_user(u["id"], is_active=False)
    assert db.authenticate_user("alice", "a-long-secure-password") is None


def test_default_admin_seeded_with_forced_change(db):
    admin = db.get_user_by_username("admin")
    assert admin is not None
    assert admin["must_change_password"] is True
    assert db.authenticate_user("admin", "admin")


def test_global_action_link_and_merge(db, tenant):
    a = db.create_action("contoso", {
        "title": "Require MFA", "source_tool": "SCuBA (CISA)", "source_id": "scuba_1"})
    ga1 = db.create_global_action_from_tenant_action(a["id"])
    assert db.get_action(a["id"])["global_action_id"] == ga1["id"]

    b = db.create_action("contoso", {
        "title": "Require MFA (dup)", "source_tool": "Zero Trust Report", "source_id": "ztr_9"})
    ga2 = db.create_global_action_from_tenant_action(b["id"])

    result = db.merge_global_actions(ga1["id"], [ga2["id"]])
    assert result["tenant_actions_relinked"] == 1
    assert db.get_action(b["id"])["global_action_id"] == ga1["id"]
    assert db.get_global_action(ga2["id"]) is None
    # Alias keeps future imports of the merged source matching
    found = db.find_global_action_for_import("Zero Trust Report", "ztr_9")
    assert found and found["id"] == ga1["id"]


def test_implementation_override(db, tenant):
    a = db.create_action("contoso", {"title": "Ctl", "source_tool": "Manual",
                                     "source_id": "m1"})
    ga = db.create_global_action_from_tenant_action(a["id"])
    db.update_global_action(ga["id"], implementation_steps="Global steps")
    assert db.get_action(a["id"])["implementation_steps"] == "Global steps"
    db.set_implementation_override("contoso", ga["id"], "Tenant-specific steps", "alice")
    got = db.get_action(a["id"])
    assert got["implementation_steps"] == "Tenant-specific steps"
    assert got["is_implementation_overridden"] is True
    db.clear_implementation_override("contoso", ga["id"])
    assert db.get_action(a["id"])["implementation_steps"] == "Global steps"
