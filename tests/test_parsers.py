"""Parser unit tests: every source format produces well-formed actions."""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from m365_posture.models import ActionStatus, Priority, SourceTool, Workload
from m365_posture.parsers import (
    M365AssessParser, ScubaParser, SCTParser, SecureScoreParser,
    ZeroTrustParser, ZeroTrustReportParser,
)
from m365_posture.parsers.zip_safety import safe_extract_zip

from .conftest import make_scuba_results


# ── Secure Score ──

SS_CSV_EN = """Rank,Recommended action,Score impact,Points achieved,Status,Category,Product,Have license?
1,Require MFA for administrative roles,+3.24 %,0/10,To address,Identity,Entra,Yes
2,Ensure all users can complete MFA,+2.10 %,5/9,Completed,Identity,Entra,Yes
"""

SS_CSV_DE = """Rang,Empfohlene Maßnahme,Bewertungsauswirkung,Erzielte Punkte,Status,Kategorie,Produkt
1,MFA für Administratorrollen anfordern,"+3,24 %",0/10,Zu behandeln,Identität,Entra
"""


def test_secure_score_csv_english(tmp_path):
    p = tmp_path / "ss.csv"
    p.write_text(SS_CSV_EN, encoding="utf-8")
    actions = SecureScoreParser().parse_file(str(p))
    assert len(actions) == 2
    a1, a2 = actions
    assert a1.title == "Require MFA for administrative roles"
    assert a1.status == ActionStatus.TODO.value
    assert a1.score == 0 and a1.max_score == 10
    assert a1.workload == Workload.ENTRA.value
    assert a1.priority == Priority.CRITICAL.value  # max_score 10 ≥ 7
    assert a2.status == ActionStatus.COMPLETED.value
    assert a2.score == 5 and a2.max_score == 9


def test_secure_score_csv_german_locale(tmp_path):
    p = tmp_path / "ss_de.csv"
    p.write_text(SS_CSV_DE, encoding="utf-8")
    actions = SecureScoreParser().parse_file(str(p))
    assert len(actions) == 1
    assert actions[0].status == ActionStatus.TODO.value
    assert actions[0].workload == Workload.ENTRA.value
    assert actions[0].max_score == 10


def test_secure_score_graph_response_with_profiles():
    data = {"value": [{
        "currentScore": 45.0, "maxScore": 60.0,
        "createdDateTime": "2026-08-01T00:00:00Z",
        "controlScores": [
            {"controlName": "AdminMFAV2", "score": 0.0,
             "controlCategory": "Identity", "description": "tenant state"},
            {"controlName": "OneAdmin", "score": 1.0,
             "controlCategory": "Identity", "description": "tenant state"},
        ],
    }]}
    profiles = {"value": [
        {"id": "AdminMFAV2", "title": "Require MFA for administrative roles",
         "maxScore": 10.0, "remediation": "Enable MFA", "userImpact": "Moderate",
         "implementationCost": "Moderate", "service": "AzureAD", "tier": "Core",
         "threats": ["Account Breach"], "actionUrl": "https://example.test"},
        {"id": "OneAdmin", "title": "Designate more than one global admin",
         "maxScore": 1.0, "service": "AzureAD"},
    ]}
    parser = SecureScoreParser()
    actions, overall = parser.parse_graph_response(data, profiles)
    assert overall["currentScore"] == 45.0 and overall["maxScore"] == 60.0
    assert len(actions) == 2
    by_sid = {a.source_id: a for a in actions}
    admin_mfa = by_sid["AdminMFAV2"]
    assert admin_mfa.title == "Require MFA for administrative roles"
    assert admin_mfa.max_score == 10.0
    assert admin_mfa.status == ActionStatus.TODO.value
    assert "Enable MFA" in admin_mfa.remediation_steps
    # Rang: sorted by max_score desc → AdminMFAV2 gets 1
    assert admin_mfa.reference_id == "1"
    assert by_sid["OneAdmin"].status == ActionStatus.COMPLETED.value


# ── SCuBA ──

def test_scuba_rich_json(tmp_path):
    p = tmp_path / "ScubaResults_x.json"
    p.write_bytes(make_scuba_results())
    parser = ScubaParser()
    actions = parser.parse_file(str(p))
    assert len(actions) == 2
    assert parser.report_metadata["tenant_id"] == "11111111-1111-1111-1111-111111111111"
    fail = next(a for a in actions if a.reference_id == "MS.AAD.1.1v1")
    assert fail.status == ActionStatus.TODO.value
    assert fail.workload == Workload.ENTRA.value
    assert fail.score == 0.0 and fail.max_score == 1.0
    ok = next(a for a in actions if a.reference_id == "MS.AAD.3.2v1")
    assert ok.status == ActionStatus.COMPLETED.value


def test_scuba_zip_roundtrip(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("M365BaselineConformance/ScubaResults_abc.json",
                    make_scuba_results())
        zf.writestr("M365BaselineConformance/BaselineReports.html", "<html></html>")
    p = tmp_path / "report.zip"
    p.write_bytes(buf.getvalue())
    parser = ScubaParser()
    actions = parser.parse_file(str(p))
    assert len(actions) == 2
    assert parser._extract_dir  # kept for report storage


def test_scuba_test_results_format(tmp_path):
    data = [
        {"PolicyId": "MS.EXO.2.2v2", "RequirementMet": False,
         "Criticality": "Shall", "ReportDetails": "SPF missing"},
        {"PolicyId": "MS.EXO.3.1v1", "RequirementMet": True,
         "Criticality": "Should", "ReportDetails": "ok"},
    ]
    p = tmp_path / "TestResults.json"
    p.write_text(json.dumps(data))
    actions = ScubaParser().parse_file(str(p))
    assert len(actions) == 2
    assert actions[0].workload == Workload.EXCHANGE.value
    assert actions[0].status == ActionStatus.TODO.value
    assert actions[1].status == ActionStatus.COMPLETED.value


def test_scuba_fallback_id_is_stable():
    """hash()-based IDs were salted per process; the digest must be stable."""
    parser = ScubaParser()
    item = {"Result": "Fail", "Details": "x"}  # no Control ID / Requirement
    a1 = parser._item_to_action(dict(item), "aad")
    a2 = parser._item_to_action(dict(item), "aad")
    assert a1.source_id == a2.source_id
    assert a1.source_id.startswith("scuba_")


def test_scuba_unsupported_extension(tmp_path):
    p = tmp_path / "report.txt"
    p.write_text("nope")
    with pytest.raises(ValueError, match="Unsupported SCuBA file format"):
        ScubaParser().parse_file(str(p))


# ── Zero Trust (report + legacy) ──

def make_zt_report(tenant_id="22222222-2222-2222-2222-222222222222") -> dict:
    return {
        "ExecutedAt": "2026-08-01T10:00:00Z",
        "TenantId": tenant_id,
        "TenantName": "Contoso",
        "Domain": "contoso.com",
        "Account": "admin@contoso.com",
        "CurrentVersion": "1.2.3",
        "TestResultSummary": {"IdentityPassed": 1, "IdentityTotal": 2},
        "TenantInfo": {},
        "Tests": [
            {"TestId": 21001, "TestTitle": "Block legacy authentication",
             "TestStatus": "Failed", "TestRisk": "High", "TestImpact": "Low",
             "TestImplementationCost": "Low", "TestPillar": "Identity",
             "TestCategory": "Access control", "TestSfiPillar": "Protect identities",
             "TestDescription": "Checked CA policies **Remediation action** Create a policy https://learn.example/ca",
             "TestResult": "No blocking policy found"},
            {"TestId": 21002, "TestTitle": "Require MFA for admins",
             "TestStatus": "Passed", "TestRisk": "High", "TestImpact": "Low",
             "TestImplementationCost": "Low", "TestPillar": "Identity",
             "TestCategory": "Access control", "TestSfiPillar": "Protect identities",
             "TestDescription": "Checked", "TestResult": "All good"},
            {"TestId": 21003, "TestTitle": "Future test",
             "TestStatus": "Planned", "TestPillar": "Devices",
             "TestCategory": "Devices",
             "TestDescription": "", "TestResult": "Planned for future release."},
        ],
    }


def test_zero_trust_report_json(tmp_path):
    p = tmp_path / "ZeroTrustAssessmentReport.json"
    p.write_text(json.dumps(make_zt_report()))
    parser = ZeroTrustReportParser()
    actions = parser.parse_file(str(p))
    assert len(actions) == 3
    assert parser.report_metadata["tenant_id"].startswith("2222")
    failed = next(a for a in actions if a.source_id == "ztr_21001")
    assert failed.status == ActionStatus.TODO.value
    assert failed.workload == Workload.ENTRA.value
    assert failed.remediation_steps.startswith("Create a policy")
    assert failed.reference_url.startswith("https://learn.example")
    planned = next(a for a in actions if a.source_id == "ztr_21003")
    assert planned.status == ActionStatus.NOT_APPLICABLE.value
    assert planned.max_score == 0.0  # N/A must not count toward score


def test_zero_trust_legacy_csv_empty_score(tmp_path):
    """Empty/odd numeric cells crashed the parser with ValueError before."""
    p = tmp_path / "zt.csv"
    p.write_text("title,score,maxScore,pillar\nSecure identities,,,Identity\n"
                 "Device compliance,50,100,Devices\n")
    actions = ZeroTrustParser().parse_file(str(p))
    assert len(actions) == 2
    assert actions[0].score == 0.0
    assert actions[0].max_score == 100.0
    assert actions[0].status == ActionStatus.TODO.value
    assert actions[1].status == ActionStatus.IN_PROGRESS.value


# ── SCT / M365-Assess ──

def test_sct_csv(tmp_path):
    p = tmp_path / "sct.csv"
    p.write_text("Setting,BaselineValue,SystemValue,MatchResult,GPOName\n"
                 "Minimum password length,14,8,Mismatch,Default Domain Policy\n"
                 "Audit logon events,Success,Success,Match,Default Domain Policy\n")
    actions = SCTParser().parse_file(str(p))
    assert actions[0].status == ActionStatus.TODO.value
    assert actions[0].current_value == "8"
    assert actions[0].recommended_value == "14"
    assert actions[1].status == ActionStatus.COMPLETED.value


def test_m365_assess_json(tmp_path):
    p = tmp_path / "assess.json"
    p.write_text(json.dumps([
        {"Check": "DKIM enabled", "Result": "Fail", "Severity": "High",
         "Module": "Exchange", "Remediation": "Enable DKIM"},
        {"Check": "Audit log", "Result": "Pass", "Severity": "Low",
         "Module": "Purview"},
    ]))
    actions = M365AssessParser().parse_file(str(p))
    assert actions[0].workload == Workload.EXCHANGE.value
    assert actions[0].priority == Priority.HIGH.value
    assert actions[0].status == ActionStatus.TODO.value
    assert actions[1].workload == Workload.PURVIEW.value
    assert actions[1].status == ActionStatus.COMPLETED.value


# ── ZIP safety guard ──

def _zip_with(files: dict) -> zipfile.ZipFile:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    buf.seek(0)
    return zipfile.ZipFile(buf)


def test_safe_extract_zip_limits(tmp_path):
    zf = _zip_with({"a.txt": "x", "b.txt": "y", "c.txt": "z"})
    with pytest.raises(ValueError, match="too many files"):
        safe_extract_zip(zf, str(tmp_path), max_files=2)
    zf = _zip_with({"big.txt": "A" * 1000})
    with pytest.raises(ValueError, match="exceeds"):
        safe_extract_zip(zf, str(tmp_path), max_total_bytes=100)
    zf = _zip_with({"ok.txt": "fine"})
    safe_extract_zip(zf, str(tmp_path))
    assert (tmp_path / "ok.txt").read_text() == "fine"
