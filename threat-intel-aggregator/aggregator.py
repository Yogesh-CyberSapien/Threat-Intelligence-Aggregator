"""
aggregator.py — Merge and deduplicate IoCs from multiple threat intel sources.

Strategy:
  - IoCs are keyed by (ioc_type, value.lower())
  - When the same indicator appears in multiple sources the records are merged:
      • votes are summed
      • threat_labels / tags / sources are union-ed
      • threat_score is re-computed from the merged votes (VT style) or
        taken as the max across all contributing records
      • country / asn / last_analysis_date keep the first non-None value
      • pulse_count is summed
"""

import logging
from typing import List, Dict, Tuple

from models import IoC

logger = logging.getLogger(__name__)

# Severity thresholds for colour-coding / filtering
SEVERITY_HIGH   = 60.0
SEVERITY_MEDIUM = 25.0


def aggregate(iocs: List[IoC]) -> List[IoC]:
    """
    Merge a flat list of IoCs (possibly from multiple sources) into a
    deduplicated list ordered by threat_score descending.
    """
    merged: Dict[Tuple[str, str], IoC] = {}

    for ioc in iocs:
        key = (ioc.ioc_type, ioc.value.lower())
        if key not in merged:
            merged[key] = _copy_ioc(ioc)
        else:
            _merge_into(merged[key], ioc)

    result = sorted(merged.values(), key=lambda x: x.threat_score, reverse=True)
    logger.info("Aggregated %d raw IoCs → %d unique indicators", len(iocs), len(result))
    return result


def severity_label(score: float) -> str:
    """Return a human-readable severity label for a threat score."""
    if score >= SEVERITY_HIGH:
        return "HIGH"
    if score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _copy_ioc(src: IoC) -> IoC:
    """Return a shallow copy of an IoC (lists are duplicated)."""
    return IoC(
        ioc_type=src.ioc_type,
        value=src.value,
        malicious_votes=src.malicious_votes,
        harmless_votes=src.harmless_votes,
        suspicious_votes=src.suspicious_votes,
        undetected_votes=src.undetected_votes,
        threat_score=src.threat_score,
        threat_labels=list(src.threat_labels),
        tags=list(src.tags),
        sources=list(src.sources),
        country=src.country,
        asn=src.asn,
        pulse_count=src.pulse_count,
        last_analysis_date=src.last_analysis_date,
        description=src.description,
    )


def _merge_into(base: IoC, other: IoC) -> None:
    """Merge *other* into *base* in place."""
    # Sum vote counts
    base.malicious_votes  += other.malicious_votes
    base.harmless_votes   += other.harmless_votes
    base.suspicious_votes += other.suspicious_votes
    base.undetected_votes += other.undetected_votes

    # Re-compute threat score from merged totals (VT-style percentage),
    # but take the max so that a high OTX pulse score isn't wiped out
    total = (
        base.malicious_votes + base.harmless_votes
        + base.suspicious_votes + base.undetected_votes
    )
    vt_score = (base.malicious_votes / total * 100.0) if total else 0.0
    base.threat_score = max(vt_score, other.threat_score, base.threat_score)

    # Union labels, tags, sources
    base.threat_labels = sorted(set(base.threat_labels) | set(other.threat_labels))
    base.tags          = sorted(set(base.tags) | set(other.tags))
    base.sources       = sorted(set(base.sources) | set(other.sources))

    # Keep first non-None enrichment
    if base.country is None:
        base.country = other.country
    if base.asn is None:
        base.asn = other.asn
    if base.last_analysis_date is None:
        base.last_analysis_date = other.last_analysis_date
    if base.description is None:
        base.description = other.description

    # Sum pulse counts
    base.pulse_count += other.pulse_count
