"""Action correlation engine - links related actions across assessment tools.

When the same security control appears in Secure Score, SCuBA, Zero Trust,
etc., this engine detects and groups them so they can be tracked together.
"""

from __future__ import annotations

import re
from .database import Database

# Canonical control families with keywords that appear across tools.
# Each entry: (canonical_name, description, keyword_patterns)
CONTROL_FAMILIES = [
    (
        "MFA Enforcement",
        "Multi-factor authentication for users and administrators",
        ["mfa", "multi-factor", "multifactor", "two-factor", "2fa", "authenticator",
         "phishing-resistant", "passwordless", "security default",
         "legacy authentication", "basic authentication",
         "modern authentication", "authentication method", "number matching",
         "conditional access.*mfa", "require mfa"],
    ),
    (
        "Privileged Access Management",
        "Restrict and protect administrative accounts",
        ["admin privilege", "privileged access", "global admin", "pim",
         "privileged identity", "just-in-time", "least privilege",
         "break glass", "emergency access", "admin account",
         "separate admin", "tiered admin", "role assignment"],
    ),
    (
        "Conditional Access Policies",
        "Risk-based access control policies",
        ["conditional access polic", "sign-in risk", "user risk",
         "device compliance.*conditional", "location.*conditional",
         "named location", "trusted location"],
    ),
    (
        "Email Authentication (SPF/DKIM/DMARC)",
        "Domain email authentication and anti-spoofing",
        ["spf", "dkim", "dmarc", "sender policy", "domainkeys",
         "domain authentication", "email authentication", "anti-spoofing"],
    ),
    (
        "Anti-Phishing Protection",
        "Protection against phishing and impersonation attacks",
        ["anti-phish", "impersonation", "phishing polic",
         "safe link", "url filtering", "click-through",
         "phishing threshold", "mailbox intelligence"],
    ),
    (
        "Anti-Malware / Safe Attachments",
        "Malware scanning and safe attachment policies",
        ["safe attachment", "malware filter", "anti-malware",
         "attachment scan", "zero-hour", "zap",
         "common attachment", "file type filter"],
    ),
    (
        "Mail Flow & Forwarding Controls",
        "External mail forwarding and transport rules",
        ["mail forward", "auto-forward", "transport rule",
         "mail flow rule", "external forward", "forwarding rule",
         "inbox rule", "remote domain"],
    ),
    (
        "Audit Logging",
        "Unified audit log and mailbox auditing",
        ["audit log", "unified audit", "mailbox audit",
         "sign-in log", "activity log", "purview audit",
         "diagnostic setting"],
    ),
    (
        "Data Loss Prevention",
        "DLP policies and sensitivity labels",
        ["data loss prevention", "dlp polic", "sensitivity label",
         "information protection", "classify.*data",
         "retention polic", "retention label"],
    ),
    (
        "Device Compliance",
        "Intune device compliance and enrollment",
        ["device compliance", "device enrollment", "intune.*compliance",
         "managed device", "mdm", "device configuration",
         "endpoint protection", "bitlocker"],
    ),
    (
        "External Sharing Controls",
        "SharePoint/OneDrive external sharing and guest access",
        ["external sharing", "guest access", "guest user",
         "anonymous link", "sharing polic", "anyone link",
         "b2b", "external collaboration"],
    ),
    (
        "Password & Credential Policies",
        "Password policies and credential management",
        ["password polic", "password expir", "password complex",
         "self-service password", "sspr", "banned password",
         "password protection", "credential"],
    ),
    (
        "Encryption & TLS",
        "Data encryption at rest and in transit",
        ["encryption", "tls", "message encrypt", "ome",
         "transport layer", "encrypt.*transit", "encrypt.*rest",
         "bitlocker", "customer key"],
    ),
    (
        "Application Control / Consent",
        "Control over third-party and OAuth applications",
        ["app consent", "application consent", "oauth",
         "enterprise application", "app registration",
         "service principal", "admin consent",
         "application control", "applocker", "wdac"],
    ),
    (
        "Teams Security",
        "Microsoft Teams communication security settings",
        ["teams.*external", "teams.*guest", "teams.*meeting",
         "teams.*messaging", "teams.*channel", "teams.*federation",
         "teams.*anonymous"],
    ),
    (
        "Power Platform Governance",
        "Power Platform DLP and environment controls",
        ["power platform.*dlp", "power platform.*environment",
         "power apps", "power automate", "dataverse",
         "connector.*restrict", "power platform.*governance"],
    ),
    (
        "Defender Configuration",
        "Microsoft Defender security configuration",
        ["defender.*polic", "defender.*alert", "defender.*incident",
         "attack surface reduction", "asr rule",
         "safe document", "defender.*endpoint"],
    ),
    (
        "Patch Management",
        "Application and OS patching",
        ["patch", "update ring", "windows update",
         "software update", "vulnerability.*patch",
         "end of life", "unsupported.*version"],
    ),
    (
        "Backup & Recovery",
        "Data backup and disaster recovery",
        ["backup", "disaster recovery", "business continuity",
         "restore", "recovery point", "retention"],
    ),
    (
        "Session Management",
        "Session timeout and sign-in frequency",
        ["session timeout", "sign-in frequency", "persistent browser",
         "idle timeout", "session lifetime", "token lifetime"],
    ),
]


def _normalize(text: str) -> str:
    """Lowercase and remove extra whitespace."""
    return re.sub(r'\s+', ' ', text.lower().strip())


def _match_family(text: str, keywords: list[str]) -> float:
    """Score how well text matches a keyword set. Returns 0-1."""
    text = _normalize(text)
    matches = 0
    for kw in keywords:
        if re.search(kw, text):
            matches += 1
    return matches / len(keywords) if keywords else 0


def auto_correlate(db: Database, tenant_name: str, threshold: float = 0.05):
    """Automatically correlate actions across tools for a tenant.

    Groups actions that likely represent the same security control.
    Only processes uncorrelated actions (correlation_group_id IS NULL).
    Uses DB-stored control families (editable via UI). Falls back to
    hardcoded CONTROL_FAMILIES if DB has no families yet.
    """
    actions = db.get_actions(tenant_name)
    uncorrelated = [a for a in actions if not a.get("correlation_group_id")]
    if not uncorrelated:
        return {"groups_created": 0, "actions_linked": 0}

    # Load families from DB; seed defaults if empty
    existing_groups = {g["canonical_name"]: g for g in db.list_correlation_groups()}

    # Build the family list from DB-stored groups + any missing defaults
    families = []
    for g in existing_groups.values():
        kw = g.get("keywords", [])
        if kw:
            families.append((g["canonical_name"], g.get("description", ""), kw))

    # If DB has no families, seed from hardcoded defaults
    if not families:
        for canonical_name, description, keywords in CONTROL_FAMILIES:
            if canonical_name not in existing_groups:
                group = db.create_correlation_group(canonical_name, description, keywords)
                existing_groups[canonical_name] = group
            families.append((canonical_name, description, keywords))

    groups_created = 0
    actions_linked = 0

    for action in uncorrelated:
        text = f"{action['title']} {action.get('description', '')} {action.get('remediation_steps', '')}"

        best_family = None
        best_score = 0

        for canonical_name, description, keywords in families:
            score = _match_family(text, keywords)
            if score > best_score and score >= threshold:
                best_score = score
                best_family = (canonical_name, description, keywords)

        if best_family:
            canonical_name, description, keywords = best_family

            if canonical_name not in existing_groups:
                group = db.create_correlation_group(
                    canonical_name, description, keywords
                )
                existing_groups[canonical_name] = group
                groups_created += 1

            group = existing_groups[canonical_name]
            db.link_action_to_group(action["id"], group["id"])
            actions_linked += 1

    return {"groups_created": groups_created, "actions_linked": actions_linked}


_STOPWORDS = {
    "the", "a", "an", "to", "for", "of", "on", "in", "is", "are", "be",
    "should", "shall", "must", "ensure", "enable", "enabled", "disable",
    "disabled", "set", "configure", "configured", "use", "used", "using",
    "all", "and", "or", "not", "with", "at", "least", "policy", "policies",
    "microsoft", "365", "m365", "office",
}


def _title_tokens(title: str) -> set:
    """Significant tokens of an action title for similarity matching."""
    words = re.findall(r"[a-z0-9]+", (title or "").lower())
    return {w for w in words if w not in _STOPWORDS and len(w) > 2}


def suggest_action_links(db: Database, tenant_name: str,
                         min_similarity: float = 0.5, limit: int = 60) -> list[dict]:
    """Suggest cross-tool action pairs that likely represent the SAME control
    (e.g. SCuBA and Secure Score both say "Disable device code authentication").

    Uses title-token similarity (Jaccard) across actions from different source
    tools, skipping pairs that are already linked, share a correlation group,
    point at the same global action, or were dismissed by the user.
    """
    from difflib import SequenceMatcher

    actions = db.get_actions(tenant_name)
    candidates = [a for a in actions if a.get("title")]

    linked = db.get_linked_pairs(tenant_name)
    dismissed = db.get_dismissed_link_pairs(tenant_name)

    # Invert token index so we only compare pairs sharing tokens
    token_index: dict = {}
    tokens_by_id = {}
    for a in candidates:
        toks = _title_tokens(a["title"])
        tokens_by_id[a["id"]] = toks
        for t in toks:
            token_index.setdefault(t, []).append(a)

    seen_pairs = set()
    suggestions = []
    for a in candidates:
        toks_a = tokens_by_id[a["id"]]
        if not toks_a:
            continue
        partners: dict = {}
        for t in toks_a:
            for b in token_index.get(t, []):
                if b["id"] == a["id"] or b["source_tool"] == a["source_tool"]:
                    continue
                partners[b["id"]] = b
        for b in partners.values():
            key = tuple(sorted((a["id"], b["id"])))
            if key in seen_pairs or key in linked or key in dismissed:
                continue
            seen_pairs.add(key)
            # Same correlation group or global action already implies a link
            if (a.get("correlation_group_id") and
                    a.get("correlation_group_id") == b.get("correlation_group_id")):
                continue
            if (a.get("global_action_id") and
                    a.get("global_action_id") == b.get("global_action_id")):
                continue
            toks_b = tokens_by_id[b["id"]]
            union = toks_a | toks_b
            jaccard = len(toks_a & toks_b) / len(union) if union else 0
            if jaccard < min_similarity:
                continue
            ratio = SequenceMatcher(None, _normalize(a["title"]),
                                    _normalize(b["title"])).ratio()
            similarity = round(max(jaccard, ratio), 2)
            if similarity < min_similarity:
                continue
            suggestions.append({
                "similarity": similarity,
                "a": {"id": a["id"], "title": a["title"], "source_tool": a["source_tool"],
                      "status": a["status"], "workload": a.get("workload", "")},
                "b": {"id": b["id"], "title": b["title"], "source_tool": b["source_tool"],
                      "status": b["status"], "workload": b.get("workload", "")},
                "status_differs": a["status"] != b["status"],
            })

    suggestions.sort(key=lambda s: -s["similarity"])
    return suggestions[:limit]


def get_correlation_summary(db: Database, tenant_name: str) -> list[dict]:
    """Get a summary of all correlation groups with their actions for a tenant."""
    groups = db.list_correlation_groups()
    result = []

    for group in groups:
        actions = db.get_correlated_actions(group["id"])
        # Only include actions for this tenant
        tenant_actions = [a for a in actions if a.get("tenant_name") == tenant_name]
        if not tenant_actions:
            continue

        sources = list(set(a["source_tool"] for a in tenant_actions))
        statuses = [a["status"] for a in tenant_actions]
        all_completed = all(s == "Completed" for s in statuses)
        any_completed = any(s == "Completed" for s in statuses)

        result.append({
            "group_id": group["id"],
            "canonical_name": group["canonical_name"],
            "description": group["description"],
            "action_count": len(tenant_actions),
            "sources": sources,
            "source_count": len(sources),
            "statuses": statuses,
            "overall_status": "Completed" if all_completed else (
                "In Progress" if any_completed else "ToDo"
            ),
            "actions": tenant_actions,
        })

    result.sort(key=lambda x: (-x["source_count"], x["canonical_name"]))
    return result
