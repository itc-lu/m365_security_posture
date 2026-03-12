"""Data models for M365 Security Posture Management."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class ActionStatus(str, Enum):
    TODO = "ToDo"
    IN_PROGRESS = "In Progress"
    IN_PLANNING = "In Planning"
    RISK_ACCEPTED = "Risk Accepted"
    COMPLETED = "Completed"
    NOT_APPLICABLE = "Not Applicable"
    THIRD_PARTY = "Third Party"


class Priority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class RiskLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"


class UserImpact(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    NONE = "None"


class ImplementationEffort(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    MINIMAL = "Minimal"


class Workload(str, Enum):
    ENTRA = "Entra ID"
    EXCHANGE = "Exchange Online"
    SHAREPOINT = "SharePoint Online"
    ONEDRIVE = "OneDrive"
    TEAMS = "Teams"
    POWER_PLATFORM = "Power Platform"
    DEFENDER = "Defender"
    INTUNE = "Intune"
    PURVIEW = "Purview"
    GENERAL = "General"


class SourceTool(str, Enum):
    SECURE_SCORE = "Microsoft Secure Score"
    SCUBA = "SCuBA (CISA)"
    ZERO_TRUST = "Zero Trust Assessment"
    SCT = "Security Compliance Toolkit"
    M365_ASSESS = "M365-Assess"
    MANUAL = "Manual"


class EssentialEightControl(str, Enum):
    APPLICATION_CONTROL = "Application Control"
    PATCH_APPLICATIONS = "Patch Applications"
    MACRO_SETTINGS = "Configure Microsoft Office Macro Settings"
    USER_APP_HARDENING = "User Application Hardening"
    RESTRICT_ADMIN = "Restrict Administrative Privileges"
    PATCH_OS = "Patch Operating Systems"
    MFA = "Multi-Factor Authentication"
    REGULAR_BACKUPS = "Regular Backups"


class EssentialEightMaturity(str, Enum):
    LEVEL_0 = "Maturity Level 0"
    LEVEL_1 = "Maturity Level 1"
    LEVEL_2 = "Maturity Level 2"
    LEVEL_3 = "Maturity Level 3"


class ComplianceFramework(str, Enum):
    NIST_800_53 = "NIST 800-53"
    CIS_M365 = "CIS Microsoft 365"
    ISO_27001 = "ISO 27001"
    ESSENTIAL_EIGHT = "Essential Eight"


@dataclass
class HistoryEntry:
    """A single point-in-time snapshot of an action's status."""
    timestamp: str
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    old_score: Optional[float] = None
    new_score: Optional[float] = None
    source_report: Optional[str] = None
    changed_by: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> HistoryEntry:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Action:
    """A single security recommendation/action item."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    description: str = ""
    source_tool: str = SourceTool.MANUAL.value
    source_id: str = ""  # Original ID from the source tool
    reference_id: str = ""  # External reference ID (e.g. Rang from Secure Score)
    workload: str = Workload.GENERAL.value
    status: str = ActionStatus.TODO.value
    priority: str = Priority.MEDIUM.value
    risk_level: str = RiskLevel.MEDIUM.value
    user_impact: str = UserImpact.LOW.value
    implementation_effort: str = ImplementationEffort.MEDIUM.value
    required_licence: str = ""
    score: Optional[float] = None
    max_score: Optional[float] = None
    score_percentage: Optional[float] = None
    essential_eight_control: Optional[str] = None
    essential_eight_maturity: Optional[str] = None
    remediation_steps: str = ""
    current_value: str = ""
    recommended_value: str = ""
    category: str = ""
    subcategory: str = ""
    planned_date: Optional[str] = None
    responsible: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    reference_url: str = ""
    source_report_file: str = ""
    source_report_date: str = ""
    raw_data: dict = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)
    # Secure Score enrichment fields
    threats: list[str] = field(default_factory=list)  # Threats mitigated (e.g. accountBreach, dataExfiltration)
    tier: str = ""  # Control tier: Core, Defense in Depth, Advanced
    action_type: str = ""  # Config, Review, Behavior
    remediation_impact: str = ""  # Impact description of implementing remediation
    deprecated: bool = False  # Whether the control is deprecated
    # Risk acceptance workflow
    risk_justification: str = ""
    risk_owner: str = ""
    risk_review_date: Optional[str] = None
    risk_expiry_date: Optional[str] = None
    risk_accepted_at: Optional[str] = None
    # Link to reference control
    control_id: Optional[str] = None
    # Dependencies
    depends_on: list[str] = field(default_factory=list)
    blocks: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> Action:
        valid_fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_fields)

    def update_status(self, new_status: str, source_report: str = "", changed_by: str = "", notes: str = ""):
        old_status = self.status
        entry = HistoryEntry(
            timestamp=datetime.utcnow().isoformat(),
            old_status=old_status,
            new_status=new_status,
            source_report=source_report or None,
            changed_by=changed_by or None,
            notes=notes or None,
        )
        self.history.append(entry.to_dict())
        self.status = new_status
        self.updated_at = datetime.utcnow().isoformat()

    def update_score(self, new_score: float, max_score: float = None, source_report: str = ""):
        old_score = self.score
        entry = HistoryEntry(
            timestamp=datetime.utcnow().isoformat(),
            old_score=old_score,
            new_score=new_score,
            source_report=source_report or None,
        )
        self.history.append(entry.to_dict())
        self.score = new_score
        if max_score is not None:
            self.max_score = max_score
        if self.max_score and self.max_score > 0:
            self.score_percentage = round((new_score / self.max_score) * 100, 2)
        self.updated_at = datetime.utcnow().isoformat()


@dataclass
class SecureScoreControl:
    """Reference data for a Microsoft Secure Score control.

    This is the static/shared metadata that is identical across all tenants.
    Per-tenant actions link to this via control_id.
    """
    id: str = ""  # Slug identifier, e.g. "AdminMFAV2"
    title: str = ""  # English display title
    description: str = ""
    remediation_steps: str = ""
    prerequisites: str = ""
    user_impact_description: str = ""
    implementation_cost: str = ""  # Easy / Moderate / Difficult
    category: str = ""  # Identity / Data / Device / Apps / Infrastructure
    product: str = ""
    reference_url: str = ""
    max_score: float = 0.0
    # Localized title variants for matching CSV imports in different languages
    title_variants: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, data: dict) -> SecureScoreControl:
        valid_fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_fields)


@dataclass
class TenantConfig:
    """Configuration for a single M365 tenant."""
    tenant_id: str = ""
    tenant_name: str = ""
    display_name: str = ""
    client_id: str = ""
    client_secret: str = ""
    certificate_path: str = ""
    use_interactive: bool = False
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        # Never serialize the secret in full for display
        return d

    @classmethod
    def from_dict(cls, data: dict) -> TenantConfig:
        valid_fields = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**valid_fields)


@dataclass
class TenantData:
    """All security posture data for a single tenant."""
    tenant: dict = field(default_factory=dict)
    actions: list[dict] = field(default_factory=list)
    import_history: list[dict] = field(default_factory=list)
    scores: dict = field(default_factory=dict)  # source_tool -> {score, max_score, date}

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> TenantData:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
