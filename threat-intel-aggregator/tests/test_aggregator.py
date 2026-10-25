"""
tests/test_aggregator.py — Unit tests for aggregator.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from models import IoC
from aggregator import aggregate, severity_label, SEVERITY_HIGH, SEVERITY_MEDIUM


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def make_ioc(ioc_type="ip", value="1.2.3.4", score=0.0, sources=None,
             malicious=0, harmless=0, suspicious=0, undetected=0,
             tags=None, labels=None, pulse_count=0, country=None, asn=None):
    return IoC(
        ioc_type=ioc_type,
        value=value,
        threat_score=score,
        malicious_votes=malicious,
        harmless_votes=harmless,
        suspicious_votes=suspicious,
        undetected_votes=undetected,
        threat_labels=labels or [],
        tags=tags or [],
        sources=sources or ["VirusTotal"],
        pulse_count=pulse_count,
        country=country,
        asn=asn,
    )


# ------------------------------------------------------------------
# severity_label
# ------------------------------------------------------------------

class TestSeverityLabel:
    def test_high(self):
        assert severity_label(SEVERITY_HIGH) == "HIGH"
        assert severity_label(90.0) == "HIGH"

    def test_medium(self):
        assert severity_label(SEVERITY_MEDIUM) == "MEDIUM"
        assert severity_label(40.0) == "MEDIUM"

    def test_low(self):
        assert severity_label(1.0) == "LOW"
        assert severity_label(SEVERITY_MEDIUM - 0.1) == "LOW"

    def test_clean(self):
        assert severity_label(0.0) == "CLEAN"


# ------------------------------------------------------------------
# aggregate — deduplication
# ------------------------------------------------------------------

class TestAggregateDeduplication:
    def test_unique_iocs_unchanged(self):
        iocs = [
            make_ioc(value="1.1.1.1"),
            make_ioc(ioc_type="domain", value="evil.com"),
        ]
        result = aggregate(iocs)
        assert len(result) == 2

    def test_duplicate_same_source_merged(self):
        iocs = [
            make_ioc(value="1.1.1.1", malicious=5, harmless=10, score=33.3),
            make_ioc(value="1.1.1.1", malicious=5, harmless=10, score=33.3),
        ]
        result = aggregate(iocs)
        assert len(result) == 1

    def test_case_insensitive_dedup(self):
        iocs = [
            make_ioc(ioc_type="domain", value="Evil.Com"),
            make_ioc(ioc_type="domain", value="evil.com"),
        ]
        result = aggregate(iocs)
        assert len(result) == 1

    def test_different_type_same_value_not_merged(self):
        iocs = [
            make_ioc(ioc_type="ip", value="1.2.3.4"),
            make_ioc(ioc_type="hash", value="1.2.3.4"),
        ]
        result = aggregate(iocs)
        assert len(result) == 2


# ------------------------------------------------------------------
# aggregate — merging vote counts and scores
# ------------------------------------------------------------------

class TestAggregateMerging:
    def test_votes_are_summed(self):
        iocs = [
            make_ioc(value="1.1.1.1", malicious=10, harmless=90),
            make_ioc(value="1.1.1.1", malicious=5,  harmless=5, sources=["AlienVault OTX"]),
        ]
        merged = aggregate(iocs)[0]
        assert merged.malicious_votes == 15
        assert merged.harmless_votes  == 95

    def test_threat_score_is_max_of_candidates(self):
        iocs = [
            make_ioc(value="1.1.1.1", score=10.0),
            make_ioc(value="1.1.1.1", score=75.0, sources=["AlienVault OTX"]),
        ]
        merged = aggregate(iocs)[0]
        assert merged.threat_score >= 75.0

    def test_sources_are_unioned(self):
        iocs = [
            make_ioc(value="1.1.1.1", sources=["VirusTotal"]),
            make_ioc(value="1.1.1.1", sources=["AlienVault OTX"]),
        ]
        merged = aggregate(iocs)[0]
        assert "VirusTotal" in merged.sources
        assert "AlienVault OTX" in merged.sources

    def test_tags_are_unioned(self):
        iocs = [
            make_ioc(value="1.1.1.1", tags=["botnet"]),
            make_ioc(value="1.1.1.1", tags=["c2", "botnet"]),
        ]
        merged = aggregate(iocs)[0]
        assert set(merged.tags) == {"botnet", "c2"}

    def test_pulse_count_summed(self):
        iocs = [
            make_ioc(value="1.1.1.1", pulse_count=3),
            make_ioc(value="1.1.1.1", pulse_count=7),
        ]
        merged = aggregate(iocs)[0]
        assert merged.pulse_count == 10

    def test_country_kept_from_first_non_none(self):
        iocs = [
            make_ioc(value="1.1.1.1", country=None),
            make_ioc(value="1.1.1.1", country="RU"),
        ]
        merged = aggregate(iocs)[0]
        assert merged.country == "RU"

    def test_country_first_value_wins(self):
        iocs = [
            make_ioc(value="1.1.1.1", country="US"),
            make_ioc(value="1.1.1.1", country="RU"),
        ]
        merged = aggregate(iocs)[0]
        assert merged.country == "US"


# ------------------------------------------------------------------
# aggregate — ordering
# ------------------------------------------------------------------

class TestAggregateOrdering:
    def test_sorted_by_score_descending(self):
        iocs = [
            make_ioc(value="low.example.com",  ioc_type="domain", score=5.0),
            make_ioc(value="high.example.com", ioc_type="domain", score=80.0),
            make_ioc(value="med.example.com",  ioc_type="domain", score=40.0),
        ]
        result = aggregate(iocs)
        scores = [r.threat_score for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_empty_list_returns_empty(self):
        assert aggregate([]) == []
