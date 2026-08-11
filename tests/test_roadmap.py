"""Tests for the roadmap features: Maester import (R1/R3), notifications
(R2), headless CI run (R4), Markdown export (R5), national clouds (R6) and
the Copilot & AI workload (R7)."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from m365_posture import notifications
from m365_posture.cli import build_parser, cmd_run
from m365_posture.database import Database
from m365_posture.graph_api import CLOUD_ENDPOINTS, cloud_endpoints
from m365_posture.import_pipeline import process_file_import
from m365_posture.models import ActionStatus, TenantConfig, Workload
from m365_posture.parsers import MaesterParser

from .conftest import STRONG_PW, XRW


# ── Maester test-results fixtures ──

def make_maester_results(tenant_id="11111111-1111-1111-1111-111111111111",
                         tests=None) -> bytes:
    if tests is None:
        tests = [
            {"Id": "MT.1001",
             "Title": "At least one Conditional Access policy is configured with device compliance",
             "Name": "MT.1001: At least one Conditional Access policy is configured with device compliance.",
             "Severity": "High", "Tag": ["MT.1001", "CA", "Security"],
             "Result": "Failed", "Block": "Conditional Access",
             "HelpUrl": "https://maester.dev/docs/tests/MT.1001",
             "ResultDetail": {
                 "TestResult": "No compliant-device policy found.",
                 "TestDescription": "Checks that device compliance is required."}},
            {"Id": "EIDSCA.AF01",
             "Title": "Authenticator app number matching is enabled",
             "Name": "EIDSCA.AF01: Authenticator app number matching is enabled.",
             "Severity": "Medium", "Tag": ["EIDSCA.AF01", "EIDSCA", "Authentication"],
             "Result": "Passed", "Block": "Authentication Methods",
             "HelpUrl": "https://maester.dev/docs/tests/EIDSCA.AF01",
             "ResultDetail": {"TestResult": "Enabled.", "TestDescription": "…"}},
            {"Id": "ORCA.100", "Title": "DKIM is enabled for all domains",
             "Name": "ORCA.100: DKIM is enabled for all domains.",
             "Severity": "High", "Tag": ["ORCA.100", "ORCA"],
             "Result": "Skipped", "Block": "Email Authentication"},
            {"Id": "MT.1050", "Title": "Copilot agents follow least privilege",
             "Name": "MT.1050: Copilot agents follow least privilege.",
             "Severity": "Medium", "Tag": ["MT.1050", "Copilot", "AI Agent"],
             "Result": "Failed", "Block": "AI Security"},
        ]
    doc = {
        "Result": "Failed",
        "TotalCount": len(tests),
        "PassedCount": sum(1 for t in tests if t.get("Result") == "Passed"),
        "FailedCount": sum(1 for t in tests if t.get("Result") == "Failed"),
        "SkippedCount": sum(1 for t in tests if t.get("Result") == "Skipped"),
        "ExecutedAt": "2026-08-10T06:00:00Z",
        "TenantId": tenant_id,
        "TenantName": "Contoso Ltd",
        "Account": "svc@contoso.com",
        "CurrentVersion": "1.1.0",
        "Tests": tests,
    }
    return json.dumps(doc).encode()


# ── R1: Maester parser ──

def test_maester_parser_json(tmp_path):
    p = tmp_path / "test-results.json"
    p.write_bytes(make_maester_results())
    parser = MaesterParser()
    actions = parser.parse_file(str(p))
    assert len(actions) == 4
    assert parser.report_metadata["tenant_id"].startswith("1111")
    assert parser.test_summary["failed"] == 2

    by_id = {a.reference_id: a for a in actions}
    ca = by_id["MT.1001"]
    assert ca.status == ActionStatus.TODO.value
    assert ca.workload == Workload.ENTRA.value
    assert ca.priority == "High"
    assert ca.source_id == "maester_MT.1001"
    assert ca.category == "Maester"
    assert ca.reference_url.startswith("https://maester.dev")
    assert "No compliant-device policy" in ca.current_value

    eidsca = by_id["EIDSCA.AF01"]
    assert eidsca.status == ActionStatus.COMPLETED.value
    assert eidsca.score == 1.0 and eidsca.max_score == 1.0
    assert eidsca.category == "EIDSCA"

    orca = by_id["ORCA.100"]
    assert orca.status == ActionStatus.NOT_APPLICABLE.value
    assert orca.max_score == 0.0  # skipped tests don't count toward score
    assert orca.workload == Workload.EXCHANGE.value


def test_maester_copilot_tests_map_to_ai_workload(tmp_path):
    p = tmp_path / "test-results.json"
    p.write_bytes(make_maester_results())
    actions = MaesterParser().parse_file(str(p))
    ai = next(a for a in actions if a.reference_id == "MT.1050")
    assert ai.workload == Workload.COPILOT.value


def test_maester_parser_zip_and_id_fallbacks(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("maester/test-results.json", make_maester_results(tests=[
            # No Id — extracted from the Name prefix
            {"Name": "CISA.MS.EXO.2.2: SPF policies published",
             "Result": "Failed", "Tag": ["CISA"], "Block": "Exchange"},
            # No Id or prefix — falls back to a stable digest
            {"Name": "Some ad-hoc custom test", "Result": "Passed"},
        ]))
        zf.writestr("maester/report.html", "<html>Maester</html>")
    p = tmp_path / "maester.zip"
    p.write_bytes(buf.getvalue())
    parser = MaesterParser()
    actions = parser.parse_file(str(p))
    assert len(actions) == 2
    assert actions[0].reference_id == "CISA.MS.EXO.2.2"
    assert parser._extract_dir
    # Digest fallback is stable across parses
    again = MaesterParser().parse_file(str(p))
    assert actions[1].source_id == again[1].source_id


def test_maester_parser_rejects_non_maester_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"foo": "bar"}))
    with pytest.raises(ValueError, match="Maester results"):
        MaesterParser().parse_file(str(p))


def test_maester_import_pipeline_stores_report(db, tenant, tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("out/test-results.json", make_maester_results())
        zf.writestr("out/MaesterReport.html", "<html>report</html>")
    p = tmp_path / "maester.zip"
    p.write_bytes(buf.getvalue())

    result = process_file_import(db, "contoso", "maester", str(p), "maester.zip")
    assert result["success"] is True
    assert result["new_actions"] == 4
    assert result["tenant_verified"] is True
    assert result["maester_report_id"]
    reports = db.get_maester_reports("contoso")
    assert reports[0]["failed_tests"] == 2
    assert reports[0]["html_path"].endswith(".html")
    # Deleting the record removes the stored files too
    db.delete_maester_report(reports[0]["id"])
    assert db.get_maester_reports("contoso") == []


def test_maester_wrong_tenant_rejected(db, tenant, tmp_path):
    from m365_posture.import_pipeline import TenantMismatchError
    p = tmp_path / "test-results.json"
    p.write_bytes(make_maester_results(tenant_id="99999999-9999-9999-9999-999999999999"))
    with pytest.raises(TenantMismatchError):
        process_file_import(db, "contoso", "maester", str(p), "r.json")


# ── R2: Notifications ──

@pytest.fixture()
def notif_db(db, tenant):
    db.set_app_setting("smtp", {"host": "smtp.test", "port": 587,
                                "username": "u", "password": "p",
                                "use_tls": True, "from_addr": "posture@test"})
    db.set_tool_config("contoso", "notifications", {
        "enabled": True,
        "emails": ["soc@test"],
        "teams_webhook": "https://teams.example/webhook",
        "slack_webhook": "",
        "events": {e: True for e in notifications.EVENTS},
        "regression_threshold": 1.0,
    })
    return db


class _FakeSMTP:
    sent = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        self.user = user

    def send_message(self, msg):
        _FakeSMTP.sent.append(msg)


def test_dispatch_sends_email_and_webhook(notif_db, monkeypatch):
    _FakeSMTP.sent = []
    webhooks = []

    class _FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self): return b"ok"

    monkeypatch.setattr(notifications.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(notifications, "urlopen",
                        lambda req, timeout=None: (webhooks.append(req), _FakeResp())[1])

    result = notifications.dispatch(notif_db, "contoso", "run_failure",
                                    "Subject line", "Body text")
    assert result["sent"] == 2 and not result["errors"]
    assert _FakeSMTP.sent[0]["Subject"] == "Subject line"
    assert _FakeSMTP.sent[0]["To"] == "soc@test"
    assert webhooks[0].full_url == "https://teams.example/webhook"
    payload = json.loads(webhooks[0].data.decode())
    assert "Subject line" in payload["text"]
    # Every send is logged
    log = notif_db.get_notification_log("contoso")
    assert {l["channel"] for l in log} == {"email", "teams"}
    assert all(l["status"] == "sent" for l in log)


def test_dispatch_respects_disabled_and_event_toggles(notif_db):
    cfg = notifications.get_notification_config(notif_db, "contoso")
    cfg["events"]["new_findings"] = False
    notif_db.set_tool_config("contoso", "notifications", cfg)
    r = notifications.dispatch(notif_db, "contoso", "new_findings", "s", "b")
    assert r["skipped"] is True and r["sent"] == 0

    cfg["enabled"] = False
    notif_db.set_tool_config("contoso", "notifications", cfg)
    r = notifications.dispatch(notif_db, "contoso", "run_failure", "s", "b")
    assert r["skipped"] is True


def test_dispatch_captures_channel_errors(notif_db, monkeypatch):
    def _boom(*a, **kw):
        raise OSError("connection refused")
    monkeypatch.setattr(notifications.smtplib, "SMTP", _boom)
    monkeypatch.setattr(notifications, "urlopen", _boom)
    result = notifications.dispatch(notif_db, "contoso", "run_failure", "s", "b")
    assert result["sent"] == 0
    assert len(result["errors"]) == 2
    assert any(l["status"] == "error" for l in notif_db.get_notification_log("contoso"))


def test_webhook_requires_https():
    with pytest.raises(RuntimeError, match="https"):
        notifications.send_webhook("http://evil.test/hook", "s", "b")


def test_notify_import_events_regression(notif_db, monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "dispatch",
                        lambda db, t, e, s, b, c=None, force=False:
                        (sent.append((e, s)), {"sent": 1, "errors": []})[1])
    result = {"drift": {"score_delta": -2.5, "current_percentage": 60,
                        "regressions": [{"scope": "SCuBA (CISA)", "old_value": 80,
                                         "new_value": 70, "delta": -10}]},
              "new_actions": 3, "total_parsed": 10, "source": "scuba"}
    notifications.notify_import_events(notif_db, "contoso", result)
    events = [e for e, _ in sent]
    assert "score_regression" in events
    assert "new_findings" in events


def test_notify_import_events_below_threshold(notif_db, monkeypatch):
    sent = []
    monkeypatch.setattr(notifications, "dispatch",
                        lambda db, t, e, s, b, c=None, force=False:
                        (sent.append(e), {"sent": 1, "errors": []})[1])
    result = {"drift": {"score_delta": -0.2, "regressions": []}, "new_actions": 0}
    notifications.notify_import_events(notif_db, "contoso", result)
    assert "score_regression" not in sent


def test_risk_expiry_digest_and_dedup(notif_db, monkeypatch):
    a = notif_db.create_action("contoso", {"title": "Accepted risky thing"})
    notif_db.accept_risk(a["id"], "why", "CISO", expiry_date="2026-08-12T00:00:00")

    calls = []
    monkeypatch.setattr(notifications, "dispatch",
                        lambda db, t, e, s, b, c=None, force=False:
                        (calls.append(s), db.add_notification_log(t, e, "email", "sent", s),
                         {"sent": 1, "errors": []})[2])
    r1 = notifications.notify_risk_expiry_digest(notif_db, "contoso")
    assert r1["sent"] == 1
    assert "risk acceptance" in calls[0]
    # Second run within the dedup window is skipped
    r2 = notifications.notify_risk_expiry_digest(notif_db, "contoso")
    assert r2["skipped"] is True
    assert len(calls) == 1


def test_run_failure_notification_from_runner(notif_db, monkeypatch):
    from m365_posture import runner
    sent = []
    monkeypatch.setattr(notifications, "dispatch",
                        lambda db, t, e, s, b, c=None, force=False:
                        (sent.append((e, s)), {"sent": 1, "errors": []})[1])
    # secure_score fails fast: no credentials configured
    run_id = runner.execute_task(notif_db, "contoso", "secure_score", trigger="manual")
    run = next(r for r in notif_db.get_tool_runs("contoso") if r["id"] == run_id)
    assert run["status"] == "error"
    assert sent and sent[0][0] == "run_failure"
    assert "secure_score" in sent[0][1]


# ── R2: Notification API endpoints ──

def test_notification_endpoints_admin_only(admin_client, analyst_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    assert analyst_client.get("/api/notifications/smtp").status_code == 403
    assert analyst_client.put("/api/notifications/smtp", json={}, headers=XRW).status_code == 403
    assert analyst_client.get("/api/tenants/contoso/notifications").status_code == 403
    assert analyst_client.put("/api/tenants/contoso/notifications",
                              json={}, headers=XRW).status_code == 403
    assert analyst_client.post("/api/tenants/contoso/notifications/test",
                               json={}, headers=XRW).status_code == 403


def test_smtp_settings_roundtrip_redacts_password(admin_client):
    r = admin_client.put("/api/notifications/smtp", headers=XRW,
                         json={"host": "smtp.test", "port": 465,
                               "username": "u", "password": "hunter2-secret",
                               "use_tls": True, "from_addr": "x@test"})
    assert r.status_code == 200
    assert r.get_json()["password"] == "***"
    r = admin_client.get("/api/notifications/smtp")
    assert r.get_json()["password"] == "***"
    assert "hunter2-secret" not in r.get_data(as_text=True)
    # Saving with *** keeps the stored password
    r = admin_client.put("/api/notifications/smtp", headers=XRW,
                         json={"host": "smtp.test", "password": "***"})
    assert r.status_code == 200
    assert r.get_json()["password"] == "***"


def test_tenant_notification_config_validation(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    r = admin_client.put("/api/tenants/contoso/notifications", headers=XRW,
                         json={"enabled": True, "emails": ["a@b"],
                               "teams_webhook": "http://not-https"})
    assert r.status_code == 400
    r = admin_client.put("/api/tenants/contoso/notifications", headers=XRW,
                         json={"enabled": True, "emails": ["a@b", " "],
                               "teams_webhook": "https://ok.example/hook",
                               "events": {"new_findings": False},
                               "regression_threshold": 2.5})
    assert r.status_code == 200
    body = r.get_json()
    assert body["emails"] == ["a@b"]
    assert body["events"]["new_findings"] is False
    assert body["regression_threshold"] == 2.5


def test_notification_test_endpoint_reports_missing_channels(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    r = admin_client.post("/api/tenants/contoso/notifications/test",
                          json={}, headers=XRW)
    assert r.status_code == 400  # no channels configured yet


# ── R3: Maester automation task ──

def test_maester_task_registered():
    from m365_posture.runner import TASK_TYPES, _TASK_RUNNERS
    assert "maester" in TASK_TYPES
    assert "maester" in _TASK_RUNNERS
    assert "maester" in Database.SCHEDULE_TASK_TYPES


def test_maester_schedule_and_tool_config_api(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    r = admin_client.put("/api/tenants/contoso/schedules/maester", headers=XRW,
                         json={"frequency": "weekly", "enabled": True})
    assert r.status_code == 200
    assert r.get_json()["frequency"] == "weekly"
    r = admin_client.put("/api/tenants/contoso/tool-config/maester", headers=XRW,
                         json={"config": {"module_path": "", "connect_command": "",
                                          "extra_args": "-Tag CA"}})
    assert r.status_code == 200
    ov = admin_client.get("/api/tenants/contoso/automation").get_json()
    assert ov["tool_configs"]["maester"]["extra_args"] == "-Tag CA"
    assert any(s["task_type"] == "maester" for s in ov["schedules"])
    # Admins see the notification config in the overview; the run task exists
    assert "notifications" in ov


def test_maester_run_fails_cleanly_without_pwsh(db, tenant, monkeypatch):
    from m365_posture import runner
    monkeypatch.setattr(runner, "find_pwsh", lambda cfg=None: None)
    with pytest.raises(RuntimeError, match="PowerShell not found"):
        runner.run_maester(db, "contoso")


# ── R4: Headless CI run mode ──

def test_cli_run_parser_wiring():
    parser = build_parser()
    args = parser.parse_args(["run", "maester", "--tenant", "contoso",
                              "--fail-on-regression", "--json"])
    assert args.func is cmd_run
    assert args.task == "maester"
    assert args.as_json is True


def test_cli_run_unknown_tenant_exits_3(db_path, capsys):
    Database(db_path)  # initialise schema
    parser = build_parser()
    args = parser.parse_args(["run", "secure_score", "--tenant", "ghost",
                              "--db", db_path])
    with pytest.raises(SystemExit) as exc:
        cmd_run(args)
    assert exc.value.code == 3
    assert "not found" in capsys.readouterr().out


def test_cli_run_failed_task_exits_1(db_path, db, tenant, capsys):
    # secure_score without credentials fails -> exit 1, error surfaced
    parser = build_parser()
    args = parser.parse_args(["run", "secure_score", "--tenant", "contoso",
                              "--db", db_path, "--json"])
    with pytest.raises(SystemExit) as exc:
        cmd_run(args)
    assert exc.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "error"
    assert out["task"] == "secure_score"


def test_cli_run_success_and_regression_exit_codes(db_path, db, tenant,
                                                   monkeypatch, capsys):
    from m365_posture import runner as runner_mod
    from m365_posture import cli as cli_mod

    def _fake_success(db_, tenant_name):
        db_.save_drift_report(
            tenant_name=tenant_name, source_tool="Maester",
            previous_snapshot_id=1, current_snapshot_id=2,
            score_before=80.0, score_after=75.0,
            regressions=[{"scope": "Maester", "old_value": 80, "new_value": 75,
                          "delta": -5.0}],
            improvements=[], new_findings=[], resolved_findings=[],
            summary="Score regressed by -5.0%")
        return {"summary": "ok", "report_id": ""}

    monkeypatch.setitem(runner_mod._TASK_RUNNERS, "maester", _fake_success)

    parser = build_parser()
    # Without --fail-on-regression: success -> exit 0
    args = parser.parse_args(["run", "maester", "--tenant", "contoso",
                              "--db", db_path, "--json"])
    with pytest.raises(SystemExit) as exc:
        cli_mod.cmd_run(args)
    assert exc.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "success"
    assert out["regressed"] is True

    # With --fail-on-regression: regression -> exit 2
    args = parser.parse_args(["run", "maester", "--tenant", "contoso",
                              "--db", db_path, "--fail-on-regression"])
    with pytest.raises(SystemExit) as exc:
        cli_mod.cmd_run(args)
    assert exc.value.code == 2


# ── R5: Markdown export ──

def test_markdown_export(admin_client):
    from .conftest import make_scuba_results
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso",
                            "tenant_id": "11111111-1111-1111-1111-111111111111"})
    data = {"source": "scuba",
            "file": (io.BytesIO(make_scuba_results()), "ScubaResults_x.json")}
    admin_client.post("/api/tenants/contoso/import", data=data,
                      headers=XRW, content_type="multipart/form-data")
    r = admin_client.get("/api/tenants/contoso/export-actions?format=md")
    assert r.status_code == 200
    assert r.mimetype == "text/markdown"
    text = r.get_data(as_text=True)
    assert text.startswith("# Security Actions")
    assert "| Title | Status |" in text
    assert "MFA SHALL be required" in text
    # Filtered export notes its filters
    r = admin_client.get("/api/tenants/contoso/export-actions?format=md&status=ToDo")
    assert "status=ToDo" in r.get_data(as_text=True)


def test_markdown_export_escapes_pipes(admin_client):
    admin_client.post("/api/tenants", json={"name": "contoso"}, headers=XRW)
    admin_client.post("/api/tenants/contoso/actions", headers=XRW,
                      json={"title": "Weird | piped\ntitle"})
    r = admin_client.get("/api/tenants/contoso/export-actions?format=md")
    assert "Weird \\| piped title" in r.get_data(as_text=True)


# ── R6: National clouds ──

def test_cloud_endpoint_resolution():
    assert cloud_endpoints("global")["graph"] == "https://graph.microsoft.com"
    assert cloud_endpoints("usgov")["login"] == "https://login.microsoftonline.us"
    assert cloud_endpoints("usgovdod")["graph"] == "https://dod-graph.microsoft.us"
    assert cloud_endpoints("china")["graph"] == "https://microsoftgraph.chinacloudapi.cn"
    # Unknown / empty fall back to global
    assert cloud_endpoints("")["graph"] == "https://graph.microsoft.com"
    assert cloud_endpoints("mars")["graph"] == "https://graph.microsoft.com"


def test_cloud_field_admin_only_and_validated(admin_client, analyst_client):
    r = admin_client.post("/api/tenants", headers=XRW,
                          json={"name": "govtenant", "cloud": "usgov"})
    assert r.status_code == 201
    assert admin_client.get("/api/tenants/govtenant").get_json()["cloud"] == "usgov"
    # Invalid cloud rejected
    r = admin_client.put("/api/tenants/govtenant", json={"cloud": "mars"}, headers=XRW)
    assert r.status_code == 400
    # Non-admin cannot change the cloud (credential-class field)
    r = analyst_client.put("/api/tenants/govtenant", json={"cloud": "global"}, headers=XRW)
    assert r.status_code == 403
    # Enums expose the cloud list for the UI
    clouds = admin_client.get("/api/enums").get_json()["clouds"]
    assert {c["id"] for c in clouds} == set(CLOUD_ENDPOINTS.keys())


def test_tenant_config_dataclass_cloud_default():
    assert TenantConfig().cloud == "global"


# ── R7 / API surface for Maester reports ──

def test_maester_report_endpoints(admin_client):
    admin_client.post("/api/tenants", headers=XRW,
                      json={"name": "contoso",
                            "tenant_id": "11111111-1111-1111-1111-111111111111"})
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("out/test-results.json", make_maester_results())
        zf.writestr("out/MaesterReport.html", "<html>maester report</html>")
    data = {"source": "maester", "file": (io.BytesIO(buf.getvalue()), "maester.zip")}
    r = admin_client.post("/api/tenants/contoso/import", data=data,
                          headers=XRW, content_type="multipart/form-data")
    assert r.status_code == 200, r.get_json()
    report_id = r.get_json()["maester_report_id"]

    reports = admin_client.get("/api/tenants/contoso/maester-reports").get_json()
    assert reports[0]["id"] == report_id
    html = admin_client.get(f"/api/maester-reports/{report_id}/html")
    assert html.status_code == 200
    assert b"maester report" in html.data
    assert admin_client.delete(f"/api/maester-reports/{report_id}",
                               headers=XRW).status_code == 200
    assert admin_client.get("/api/tenants/contoso/maester-reports").get_json() == []


def test_copilot_workload_in_enums(admin_client):
    enums = admin_client.get("/api/enums").get_json()
    assert "Copilot & AI" in enums["workloads"]
    assert "Maester" in enums["source_tools"]
    assert "maester" in enums["import_sources"]
