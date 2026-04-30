"""Compliance framework mapping engine.

Maps security actions to controls across multiple frameworks:
- NIST 800-53 (Rev 5)
- CIS Microsoft 365 Foundations Benchmark
- ISO 27001:2022
- Essential Eight (handled separately in essential_eight.py)

Uses keyword matching against action titles, descriptions, and remediation steps.
"""

from __future__ import annotations

from .models import ComplianceFramework
from .database import Database

# NIST 800-53 Rev 5 control families relevant to M365
NIST_800_53_MAPPINGS = [
    # Access Control (AC)
    (["mfa", "multi-factor", "multifactor", "two-factor", "2fa", "authenticator",
      "phishing-resistant", "passwordless"],
     "AC-7", "Unsuccessful Logon Attempts", "Access Control"),
    (["conditional access", "sign-in risk", "user risk", "location.*access",
      "device compliance.*access", "named location"],
     "AC-2", "Account Management", "Access Control"),
    (["admin privilege", "privileged access", "global admin", "least privilege",
      "pim", "just-in-time", "privileged role"],
     "AC-6", "Least Privilege", "Access Control"),
    (["session timeout", "sign-in frequency", "idle timeout", "token lifetime",
      "persistent browser", "session lifetime"],
     "AC-12", "Session Termination", "Access Control"),
    (["guest access", "external.*user", "b2b", "external collaboration",
      "external sharing"],
     "AC-21", "Information Sharing", "Access Control"),
    (["legacy authentication", "basic authentication", "modern authentication"],
     "AC-17", "Remote Access", "Access Control"),

    # Audit and Accountability (AU)
    (["audit log", "unified audit", "mailbox audit", "sign-in log",
      "activity log", "purview audit", "diagnostic setting"],
     "AU-2", "Audit Events", "Audit and Accountability"),
    (["log retention", "audit retention", "audit log.*retention"],
     "AU-11", "Audit Record Retention", "Audit and Accountability"),
    (["alert polic", "security alert", "incident alert"],
     "AU-5", "Response to Audit Processing Failures", "Audit and Accountability"),

    # Configuration Management (CM)
    (["security baseline", "security default", "baseline.*configur",
      "hardening", "attack surface reduction", "asr rule"],
     "CM-6", "Configuration Settings", "Configuration Management"),
    (["application control", "applocker", "wdac", "software restriction"],
     "CM-7", "Least Functionality", "Configuration Management"),
    (["office macro", "vba", "macro setting", "macro security"],
     "CM-7", "Least Functionality", "Configuration Management"),

    # Identification and Authentication (IA)
    (["password polic", "password expir", "password complex", "banned password",
      "password protection", "self-service password", "sspr"],
     "IA-5", "Authenticator Management", "Identification and Authentication"),
    (["mfa", "multi-factor", "authenticator", "fido", "phishing-resistant"],
     "IA-2", "Identification and Authentication", "Identification and Authentication"),

    # Incident Response (IR)
    (["incident.*response", "security incident", "breach", "compromise"],
     "IR-4", "Incident Handling", "Incident Response"),

    # System and Communications Protection (SC)
    (["encryption", "tls", "message encrypt", "ome", "transport layer",
      "customer key", "bitlocker"],
     "SC-8", "Transmission Confidentiality", "System and Communications Protection"),
    (["spf", "dkim", "dmarc", "sender policy", "email authentication",
      "anti-spoofing"],
     "SC-7", "Boundary Protection", "System and Communications Protection"),
    (["dlp", "data loss prevention", "sensitivity label", "information protection"],
     "SC-28", "Protection of Information at Rest", "System and Communications Protection"),

    # System and Information Integrity (SI)
    (["anti-phish", "phishing", "impersonation", "safe link", "url filter"],
     "SI-8", "Spam Protection", "System and Information Integrity"),
    (["anti-malware", "malware filter", "safe attachment", "zero-hour", "zap"],
     "SI-3", "Malicious Code Protection", "System and Information Integrity"),
    (["patch", "update", "vulnerability", "end of life", "unsupported"],
     "SI-2", "Flaw Remediation", "System and Information Integrity"),

    # Contingency Planning (CP)
    (["backup", "recovery", "restore", "retention", "disaster recovery",
      "business continuity"],
     "CP-9", "Information System Backup", "Contingency Planning"),

    # Media Protection (MP)
    (["external sharing", "anonymous link", "anyone link", "sharing polic"],
     "MP-5", "Media Transport", "Media Protection"),
]

# CIS Microsoft 365 Foundations Benchmark v3.x sections
CIS_M365_MAPPINGS = [
    # 1. Account / Authentication
    (["mfa", "multi-factor", "multifactor", "two-factor", "2fa",
      "security default", "legacy authentication", "modern authentication"],
     "1.1", "Ensure MFA is enabled for all users", "Account / Authentication"),
    (["conditional access", "sign-in risk", "user risk"],
     "1.2", "Conditional Access Policies", "Account / Authentication"),
    (["global admin", "admin account", "privileged.*role", "admin.*count"],
     "1.3", "Limit Global Administrators", "Account / Authentication"),
    (["password.*expir", "password.*polic", "password.*complex"],
     "1.4", "Password Policies", "Account / Authentication"),
    (["self-service password", "sspr"],
     "1.5", "Self-Service Password Reset", "Account / Authentication"),
    (["guest access", "external.*user", "b2b"],
     "1.6", "Guest Access Settings", "Account / Authentication"),

    # 2. Application Permissions
    (["app consent", "application consent", "oauth", "admin consent",
      "app registration", "enterprise application"],
     "2.1", "Application Consent and Permissions", "Application Permissions"),
    (["service principal", "app.*permission"],
     "2.2", "Service Principal Management", "Application Permissions"),

    # 3. Data Management
    (["dlp", "data loss prevention", "sensitivity label",
      "information protection", "retention"],
     "3.1", "Data Loss Prevention Policies", "Data Management"),
    (["external sharing", "anonymous link", "anyone link", "sharing polic"],
     "3.2", "External Sharing Policies", "Data Management"),

    # 4. Email Security / Exchange Online
    (["spf", "dkim", "dmarc", "sender policy", "email authentication"],
     "4.1", "Email Authentication (SPF/DKIM/DMARC)", "Email Security"),
    (["anti-phish", "phishing", "impersonation", "safe link"],
     "4.2", "Anti-Phishing Policies", "Email Security"),
    (["safe attachment", "anti-malware", "malware filter"],
     "4.3", "Anti-Malware Policies", "Email Security"),
    (["mail forward", "auto-forward", "external forward", "transport rule"],
     "4.4", "Mail Forwarding Controls", "Email Security"),
    (["audit log", "unified audit", "mailbox audit"],
     "4.5", "Audit Logging", "Email Security"),

    # 5. Microsoft Defender
    (["defender", "safe document", "attack surface reduction", "asr"],
     "5.1", "Defender Configuration", "Microsoft Defender"),

    # 6. Microsoft Teams
    (["teams.*external", "teams.*guest", "teams.*meeting", "teams.*federation"],
     "6.1", "Teams External Access and Guest Settings", "Microsoft Teams"),

    # 7. SharePoint and OneDrive
    (["sharepoint.*sharing", "onedrive.*sharing", "external sharing"],
     "7.1", "SharePoint Sharing Policies", "SharePoint and OneDrive"),

    # 8. Power Platform
    (["power platform", "power apps", "power automate", "connector.*restrict"],
     "8.1", "Power Platform DLP and Governance", "Power Platform"),
]

# ISO 27001:2022 Annex A controls relevant to M365
ISO_27001_MAPPINGS = [
    (["mfa", "multi-factor", "two-factor", "authenticator", "passwordless"],
     "A.8.5", "Secure Authentication", "Technology"),
    (["admin privilege", "privileged access", "least privilege", "pim", "admin account"],
     "A.8.2", "Privileged Access Rights", "Technology"),
    (["access control", "conditional access", "access polic"],
     "A.5.15", "Access Control", "Organizational"),
    (["audit log", "unified audit", "monitoring", "sign-in log"],
     "A.8.15", "Logging", "Technology"),
    (["patch", "update", "vulnerability", "end of life"],
     "A.8.8", "Management of Technical Vulnerabilities", "Technology"),
    (["encryption", "tls", "message encrypt", "bitlocker"],
     "A.8.24", "Use of Cryptography", "Technology"),
    (["backup", "recovery", "restore", "business continuity"],
     "A.8.13", "Information Backup", "Technology"),
    (["dlp", "data loss prevention", "information protection", "sensitivity"],
     "A.5.12", "Classification of Information", "Organizational"),
    (["anti-malware", "malware", "safe attachment", "anti-phish"],
     "A.8.7", "Protection Against Malware", "Technology"),
    (["password polic", "credential", "authenticator management"],
     "A.5.17", "Authentication Information", "Organizational"),
    (["incident", "breach", "security event"],
     "A.5.24", "Information Security Incident Management", "Organizational"),
    (["external sharing", "guest access", "third party"],
     "A.5.19", "Information Security in Supplier Relationships", "Organizational"),
    (["device compliance", "endpoint", "mdm", "intune"],
     "A.8.1", "User Endpoint Devices", "Technology"),
    (["spf", "dkim", "dmarc", "email authentication"],
     "A.8.23", "Web Filtering", "Technology"),
    (["session timeout", "idle timeout", "token lifetime"],
     "A.8.5", "Secure Authentication", "Technology"),
]

FRAMEWORK_MAPPINGS = {
    ComplianceFramework.NIST_800_53.value: NIST_800_53_MAPPINGS,
    ComplianceFramework.CIS_M365.value: CIS_M365_MAPPINGS,
    ComplianceFramework.ISO_27001.value: ISO_27001_MAPPINGS,
}


def _match_action(text: str, keywords: list[str]) -> bool:
    """Check if action text matches any keyword patterns."""
    import re
    text = text.lower()
    for kw in keywords:
        if re.search(kw, text):
            return True
    return False


def map_action_to_frameworks(action_dict: dict) -> list[dict]:
    """Map a single action to all matching compliance framework controls.

    Returns list of {framework, control_id, control_name, control_family}.
    """
    text = f"{action_dict.get('title', '')} {action_dict.get('description', '')} " \
           f"{action_dict.get('remediation_steps', '')}"

    mappings = []
    seen = set()

    for framework, rules in FRAMEWORK_MAPPINGS.items():
        for keywords, control_id, control_name, control_family in rules:
            if _match_action(text, keywords):
                key = (framework, control_id)
                if key not in seen:
                    seen.add(key)
                    mappings.append({
                        "framework": framework,
                        "control_id": control_id,
                        "control_name": control_name,
                        "control_family": control_family,
                    })

    return mappings


def auto_map_global_compliance(db: Database, frameworks: list[str] = None) -> dict:
    """Auto-map every global action to compliance frameworks. Mappings live on
    the global action so the work is shared across all tenants."""
    frameworks_to_map = frameworks or list(FRAMEWORK_MAPPINGS.keys())
    total = 0
    by_framework = {}
    global_actions = db.list_global_actions()
    for ga in global_actions:
        # Compose a synthetic action dict that map_action_to_frameworks can read.
        synth = {
            "title": ga.get("title", ""),
            "description": ga.get("description", ""),
            "remediation_steps": ga.get("implementation_steps", ""),
            "category": ga.get("category", ""),
            "subcategory": ga.get("subcategory", ""),
            "essential_eight_control": ga.get("essential_eight_control"),
        }
        existing = {(m["framework"], m["control_id"]) for m in db.get_global_compliance_mappings(ga["id"])}
        for m in map_action_to_frameworks(synth):
            if m["framework"] not in frameworks_to_map:
                continue
            key = (m["framework"], m["control_id"])
            if key in existing:
                continue
            db.add_global_compliance_mapping(
                ga["id"], m["framework"], m["control_id"],
                m.get("control_name", ""), m.get("control_family", ""),
            )
            by_framework[m["framework"]] = by_framework.get(m["framework"], 0) + 1
            total += 1
    return {"total_mappings": total, "by_framework": by_framework, "scope": "global"}


def auto_map_compliance(db: Database, tenant_name: str,
                        frameworks: list[str] = None) -> dict:
    """Auto-map a tenant's compliance posture. Framework correlations live on
    the global action; this helper drives the global mapper plus a legacy
    fallback for any tenant action not yet linked to a global action."""
    frameworks_to_map = frameworks or list(FRAMEWORK_MAPPINGS.keys())
    global_result = auto_map_global_compliance(db, frameworks_to_map)

    # Legacy: handle un-globalized actions in this tenant by writing to the
    # per-tenant compliance_mappings table so the dashboard still has data.
    actions = [a for a in db.get_actions(tenant_name) if not a.get("global_action_id")]
    for fw in frameworks_to_map:
        db.clear_compliance_mappings(tenant_name, fw)
    legacy = []
    by_framework = dict(global_result["by_framework"])
    total = global_result["total_mappings"]
    for action in actions:
        for m in map_action_to_frameworks(action):
            if m["framework"] not in frameworks_to_map:
                continue
            legacy.append({"action_id": action["id"], **m})
            by_framework[m["framework"]] = by_framework.get(m["framework"], 0) + 1
            total += 1
    if legacy:
        db.bulk_add_compliance_mappings(legacy)

    return {"total_mappings": total, "by_framework": by_framework}
