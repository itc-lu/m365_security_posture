"""Parsers for various M365 security assessment tools."""

from .secure_score import (
    SecureScoreParser,
    enrich_actions_from_controls,
    load_seed_controls,
    parse_graph_control_profiles,
)
from .scuba import ScubaParser
from .zero_trust import ZeroTrustParser
from .sct import SCTParser
from .m365_assess import M365AssessParser
from .zero_trust_report import ZeroTrustReportParser
from .maester import MaesterParser

__all__ = [
    "SecureScoreParser",
    "ScubaParser",
    "ZeroTrustParser",
    "ZeroTrustReportParser",
    "SCTParser",
    "M365AssessParser",
    "MaesterParser",
    "enrich_actions_from_controls",
    "load_seed_controls",
    "parse_graph_control_profiles",
]
