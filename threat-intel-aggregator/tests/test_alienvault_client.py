"""
tests/test_alienvault_client.py — Unit tests for alienvault_client.py (mocked HTTP)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest
import math

with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_vt_key", "ALIENVAULT_API_KEY": "test_otx_key"}):
    from alienvault_client import AlienVaultClient


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _mock_otx_indicator(pulse_count=5, tags=None, country="US", asn="AS1234"):
    tags = tags or ["malware", "c2"]
    pulses = [{"name": f"Pulse {i}", "tags": tags} for i in range(pulse_count)]
    return {
        "pulse_info": {
            "count": pulse_count,
            "pulses": pulses,
        },
        "country_code": country,
        "asn": asn,
    }


def _mock_pulse_response(n_pulses=2, indicators_per_pulse=3):
    pulses = []
    for p in range(n_pulses):
        indicators = []
        for i in range(indicators_per_pulse):
            indicators.append({
                "type": "IPv4",
                "indicator": f"10.{p}.{i}.1",
                "description": f"C2 server pulse {p}",
            })
        pulses.append({
            "name": f"Test Pulse {p}",
            "tags": ["botnet"],
            "indicators": indicators,
        })
    return {"results": pulses}


@pytest.fixture
def otx_client():
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_vt_key", "ALIENVAULT_API_KEY": "test_otx_key"}):
        return AlienVaultClient()


# ------------------------------------------------------------------
# _parse_indicator
# ------------------------------------------------------------------

class TestParseIndicator:
    def test_basic_ip(self):
        data = _mock_otx_indicator(pulse_count=3, country="DE", asn="AS9876")
        ioc = AlienVaultClient._parse_indicator(data, ioc_type="ip", value="5.5.5.5")

        assert ioc.ioc_type == "ip"
        assert ioc.value == "5.5.5.5"
        assert ioc.pulse_count == 3
        assert ioc.country == "DE"
        assert ioc.asn == "AS9876"
        assert "AlienVault OTX" in ioc.sources

    def test_threat_score_scales_with_pulse_count(self):
        low  = AlienVaultClient._parse_indicator(_mock_otx_indicator(pulse_count=1),  "ip", "x")
        high = AlienVaultClient._parse_indicator(_mock_otx_indicator(pulse_count=100), "ip", "x")
        assert high.threat_score > low.threat_score

    def test_threat_score_capped_at_100(self):
        data = _mock_otx_indicator(pulse_count=99999)
        ioc = AlienVaultClient._parse_indicator(data, "ip", "x")
        assert ioc.threat_score <= 100.0

    def test_tags_are_deduplicated(self):
        # Same tag appears in multiple pulses
        data = _mock_otx_indicator(pulse_count=5, tags=["botnet", "botnet", "c2"])
        ioc = AlienVaultClient._parse_indicator(data, "domain", "evil.com")
        assert ioc.tags.count("botnet") == 1

    def test_zero_pulses_zero_score(self):
        data = _mock_otx_indicator(pulse_count=0)
        ioc = AlienVaultClient._parse_indicator(data, "ip", "clean.ip")
        assert ioc.threat_score == 0.0

    def test_missing_country_is_none(self):
        data = {"pulse_info": {"count": 0, "pulses": []}}
        ioc = AlienVaultClient._parse_indicator(data, "ip", "x")
        assert ioc.country is None


# ------------------------------------------------------------------
# _parse_pulse_indicator
# ------------------------------------------------------------------

class TestParsePulseIndicator:
    def test_ipv4_mapped_to_ip(self):
        ind = {"type": "IPv4", "indicator": "192.168.1.1", "description": ""}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "Test Pulse", [])
        assert ioc is not None
        assert ioc.ioc_type == "ip"
        assert ioc.value == "192.168.1.1"

    def test_domain_type_mapped(self):
        ind = {"type": "domain", "indicator": "evil.com", "description": ""}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "Pulse", [])
        assert ioc is not None
        assert ioc.ioc_type == "domain"

    def test_hash_types_mapped(self):
        for hash_type in ["FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256"]:
            ind = {"type": hash_type, "indicator": "abc123", "description": ""}
            ioc = AlienVaultClient._parse_pulse_indicator(ind, "Pulse", [])
            assert ioc is not None
            assert ioc.ioc_type == "hash"

    def test_unknown_type_returns_none(self):
        ind = {"type": "email", "indicator": "bad@evil.com", "description": ""}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "Pulse", [])
        assert ioc is None

    def test_empty_value_returns_none(self):
        ind = {"type": "IPv4", "indicator": "", "description": ""}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "Pulse", [])
        assert ioc is None

    def test_description_fallback_to_pulse_name(self):
        ind = {"type": "IPv4", "indicator": "1.2.3.4", "description": ""}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "My Pulse Name", [])
        assert ioc.description == "My Pulse Name"

    def test_description_prefers_indicator_field(self):
        ind = {"type": "IPv4", "indicator": "1.2.3.4", "description": "Direct description"}
        ioc = AlienVaultClient._parse_pulse_indicator(ind, "Pulse Name", [])
        assert ioc.description == "Direct description"


# ------------------------------------------------------------------
# fetch_subscribed_pulses — mocked HTTP
# ------------------------------------------------------------------

class TestFetchSubscribedPulses:
    def test_returns_flat_list_of_iocs(self, otx_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _mock_pulse_response(n_pulses=2, indicators_per_pulse=3)
        otx_client._session.get = MagicMock(return_value=mock_resp)

        result = otx_client.fetch_subscribed_pulses(limit=5)
        assert len(result) == 6   # 2 pulses × 3 indicators each

    def test_unknown_indicator_types_skipped(self, otx_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "results": [{
                "name": "P",
                "tags": [],
                "indicators": [
                    {"type": "email",  "indicator": "x@y.com", "description": ""},
                    {"type": "IPv4",   "indicator": "1.1.1.1",  "description": ""},
                ],
            }]
        }
        otx_client._session.get = MagicMock(return_value=mock_resp)

        result = otx_client.fetch_subscribed_pulses()
        assert len(result) == 1   # only the IPv4

    def test_empty_pulse_list_returns_empty(self, otx_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"results": []}
        otx_client._session.get = MagicMock(return_value=mock_resp)

        result = otx_client.fetch_subscribed_pulses()
        assert result == []


# ------------------------------------------------------------------
# fetch_iocs — dispatch and error handling
# ------------------------------------------------------------------

class TestFetchIocs:
    def test_unsupported_type_raises(self, otx_client):
        with pytest.raises(ValueError, match="Unsupported IoC type"):
            otx_client.fetch_iocs("email", ["x@y.com"])

    def test_failed_request_logged_not_raised(self, otx_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 403")
        otx_client._session.get = MagicMock(return_value=mock_resp)

        result = otx_client.fetch_iocs("ip", ["1.2.3.4"])
        assert result == []

    def test_batch_returns_multiple_iocs(self, otx_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _mock_otx_indicator()
        otx_client._session.get = MagicMock(return_value=mock_resp)

        result = otx_client.fetch_iocs("ip", ["1.2.3.4", "5.6.7.8"])
        assert len(result) == 2
