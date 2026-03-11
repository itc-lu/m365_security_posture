"""Parsers for various M365 security assessment tools."""

from .secure_score import SecureScoreParser
from .scuba import ScubaParser
from .zero_trust import ZeroTrustParser
from .sct import SCTParser
from .m365_assess import M365AssessParser

__all__ = [
    "SecureScoreParser",
    "ScubaParser",
    "ZeroTrustParser",
    "SCTParser",
    "M365AssessParser",
]
