"""Unit tests for the calculation engines: scoring, planner, correlation,
compliance, Essential Eight, xlsx and GitLab export."""

from __future__ import annotations

import shlex
import zipfile
import io

from m365_posture.compliance import map_action_to_frameworks
from m365_posture.correlation import _match_family, _title_tokens
from m365_posture.essential_eight import (
    apply_e8_mapping, get_e8_summary, map_action_to_e8,
)
from m365_posture.gitlab_export import (
    export_to_gitlab_csv, generate_gitlab_script,
)
from m365_posture.models import Action, ActionStatus
from m365_posture.planner import _licence_tier, calculate_action_roi
from m365_posture.scoring import combined_percentage
from m365_posture.xlsx import make_xlsx


# ── Scoring ──

def test_combined_percentage_averages_tools_not_points():
    by_tool = {
        "Microsoft Secure Score": {"score": 650, "max_score": 1300},  # 50%
        "SCuBA (CISA)": {"score": 130, "max_score": 130},             # 100%
    }
    # Averaged per tool: (50 + 100) / 2 = 75 — NOT dominated by the big pool
    assert combined_percentage(by_tool) == 75.0


def test_combined_percentage_skips_empty_and_supports_weights():
    by_tool = {
        "A": {"score": 50, "max_score": 100},
        "B": {"score": 0, "max_score": 0},  # no data — must be excluded
    }
    assert combined_percentage(by_tool) == 50.0
    weighted = combined_percentage(
        {"A": {"score": 100, "max_score": 100}, "C": {"score": 0, "max_score": 100}},
        weights={"A": 3.0, "C": 1.0})
    assert weighted == 75.0
    assert combined_percentage({}) == 0.0


# ── Planner ──

def test_roi_formula():
    action = {"risk_level": "High", "priority": "High", "max_score": 10,
              "implementation_effort": "Low", "user_impact": "Low"}
    # (4 * 4 * 10) / (2 * (1 + 1)) = 40.0
    assert calculate_action_roi(action) == 40.0


def test_roi_defaults_missing_max_score_to_one():
    action = {"risk_level": "Medium", "priority": "Medium", "max_score": None,
              "implementation_effort": "Medium", "user_impact": "Low"}
    # (3 * 3 * 1) / (3 * 2) = 1.5
    assert calculate_action_roi(action) == 1.5


def test_licence_tier_mapping():
    assert _licence_tier("") == 0
    assert _licence_tier("Included") == 0
    assert _licence_tier("Microsoft 365 E3") == 1
    assert _licence_tier("Entra ID P2") == 2
    assert _licence_tier("Some Unknown Add-on") == 1


# ── Correlation ──

def test_match_family_and_tokens():
    score = _match_family("Require MFA for all users", ["mfa", "passwordless"])
    assert score > 0
    assert _match_family("Nothing relevant here", ["mfa"]) == 0
    toks = _title_tokens("Ensure that MFA is enabled for all users")
    assert "mfa" in toks and "users" in toks
    # Stopwords removed: filler words and generic verbs like "enabled"
    assert {"the", "all", "ensure", "enabled"} & toks == set()


# ── Compliance mapping ──

def test_map_mfa_action_to_frameworks():
    action = {"title": "Require MFA for administrative roles",
              "description": "Multi-factor authentication protects privileged accounts",
              "remediation_steps": ""}
    mappings = map_action_to_frameworks(action)
    frameworks = {(m["framework"], m["control_id"]) for m in mappings}
    assert ("NIST 800-53", "IA-2") in frameworks
    assert ("CIS Microsoft 365", "1.1") in frameworks
    assert ("ISO 27001", "A.8.5") in frameworks


def test_map_unrelated_action_maps_nothing():
    assert map_action_to_frameworks(
        {"title": "Rename the coffee machine", "description": "", "remediation_steps": ""}
    ) == []


# ── Essential Eight ──

def test_map_action_to_e8_mfa_keywords():
    a = Action(title="Require multi-factor authentication for admins")
    control, maturity = map_action_to_e8(a)
    assert control == "Multi-Factor Authentication"
    assert maturity == "Maturity Level 1"


def test_e8_maturity_level3_indicator():
    a = Action(title="Enforce phishing-resistant MFA (FIDO2) for all users")
    control, maturity = map_action_to_e8(a)
    assert control == "Multi-Factor Authentication"
    assert maturity == "Maturity Level 3"


def test_e8_summary_achieved_maturity():
    actions = []
    for i in range(5):
        actions.append(Action(
            title=f"MFA control {i}",
            status=(ActionStatus.COMPLETED.value if i < 4 else ActionStatus.TODO.value),
            essential_eight_control="Multi-Factor Authentication",
            essential_eight_maturity="Maturity Level 1",
        ))
    summary = get_e8_summary(actions, target_maturity="Maturity Level 3")
    mfa = summary["controls"]["Multi-Factor Authentication"]
    # 4/5 = 80% ≥ threshold → ML1 achieved; no ML2 data → stops there
    assert mfa["achieved_maturity"] == "Maturity Level 1"
    assert mfa["gap_to_target"] == 2
    assert summary["overall"]["overall_achieved_maturity"] == "Maturity Level 1"


def test_apply_e8_mapping_does_not_overwrite():
    a = Action(title="Require MFA", essential_eight_control="Regular Backups",
               essential_eight_maturity="Maturity Level 2")
    apply_e8_mapping([a])
    assert a.essential_eight_control == "Regular Backups"  # untouched


# ── XLSX writer ──

def test_make_xlsx_valid_and_escaped():
    content = make_xlsx(
        ["Title", "Count"],
        [["<script>alert('x')</script>", 3],
         ["Null\x00Byte", 1.5],
         [None, ""]],
        sheet_name="Bad[Name]*?")
    zf = zipfile.ZipFile(io.BytesIO(content))
    names = set(zf.namelist())
    assert "xl/worksheets/sheet1.xml" in names
    sheet = zf.read("xl/worksheets/sheet1.xml").decode()
    assert "<script>" not in sheet            # escaped
    assert "&lt;script&gt;" in sheet
    assert "Null\x00" not in sheet            # illegal XML chars stripped
    assert "NullByte" in sheet
    workbook = zf.read("xl/workbook.xml").decode()
    assert "Bad[Name]" not in workbook        # sheet name sanitized


# ── GitLab export ──

def _sample_actions():
    return [Action(
        title="Fix $(touch /tmp/pwned) `whoami` \"quoted\" control",
        workload="Entra ID", priority="High", status="ToDo",
        source_tool="SCuBA (CISA)", source_id="scuba_x",
        planned_date="2026-09-01", responsible="Alice O'Hara; rm -rf /",
    )]


def test_gitlab_script_is_shell_safe(tmp_path):
    out = tmp_path / "issues.sh"
    generate_gitlab_script(_sample_actions(), str(out), "Contoso",
                           project_path="group/proj")
    script = out.read_text()
    glab_line = next(l for l in script.splitlines() if l.startswith("glab "))
    tokens = shlex.split(glab_line)
    # The full malicious title must survive as ONE argv token after --title —
    # i.e. no command substitution can occur when the script runs.
    title_idx = tokens.index("--title") + 1
    assert tokens[title_idx] == "[Entra ID] Fix $(touch /tmp/pwned) `whoami` \"quoted\" control"
    assignee_idx = tokens.index("--assignee") + 1
    assert tokens[assignee_idx] == "Alice O'Hara; rm -rf /"


def test_gitlab_csv_export(tmp_path):
    out = tmp_path / "issues.csv"
    export_to_gitlab_csv(_sample_actions(), str(out), "Contoso")
    text = out.read_text()
    assert text.splitlines()[0] == "title,description,due_date,labels,assignee"
    assert "priority::high" in text
    assert "workload::entra-id" in text


def test_gitlab_csv_status_filter(tmp_path):
    out = tmp_path / "issues.csv"
    export_to_gitlab_csv(_sample_actions(), str(out), "Contoso",
                         filter_status=["Completed"])
    assert len(out.read_text().strip().splitlines()) == 1  # header only
