"""
models.py — Shared data model for a normalized Indicator of Compromise (IoC).
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class IoC:
    """
    A normalized Indicator of Compromise pulled from one or more sources.
    """
    # Core identity
    ioc_type: str           # "ip", "domain", "url", "hash"
    value: str              # The actual indicator value

    # Threat context
    malicious_votes: int = 0
    harmless_votes: int = 0
    suspicious_votes: int = 0
    undetected_votes: int = 0

    threat_score: float = 0.0          # 0–100 normalised risk score
    threat_labels: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Source attribution
    sources: List[str] = field(default_factory=list)

    # Optional enrichment
    country: Optional[str] = None
    asn: Optional[str] = None
    pulse_count: int = 0               # AlienVault pulses referencing this IoC
    last_analysis_date: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "threat_score": round(self.threat_score, 2),
            "malicious_votes": self.malicious_votes,
            "harmless_votes": self.harmless_votes,
            "suspicious_votes": self.suspicious_votes,
            "undetected_votes": self.undetected_votes,
            "threat_labels": self.threat_labels,
            "tags": self.tags,
            "sources": self.sources,
            "country": self.country,
            "asn": self.asn,
            "pulse_count": self.pulse_count,
            "last_analysis_date": self.last_analysis_date,
            "description": self.description,
        }
