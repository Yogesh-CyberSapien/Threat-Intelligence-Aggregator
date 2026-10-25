"""
tests/test_virustotal_client.py — Unit tests for virustotal_client.py (mocked HTTP)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import MagicMock, patch
import pytest

# Patch Config before importing the client so it never reads .env
with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_vt_key", "ALIENVAULT_API_KEY": "test_otx_key"}):
    from virustotal_client import VirusTotalClient


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def _mock_vt_response(malicious=10, harmless=50, suspicious=2, undetected=30,
                      tags=None, country=None, asn=None, epoch=None, labels=None):
    """Build a minimal VT v3 API response dict."""
    labels = labels or []
    analysis_results = {
        f"engine_{i}": {"category": "malicious", "result": lbl}
        for i, lbl in enumerate(labels)
    }
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "harmless": harmless,
                    "suspicious": suspicious,
                    "undetected": undetected,
                },
                "last_analysis_results": analysis_results,
                "last_analysis_date": epoch or 1700000000,
                "tags": tags or [],
                "country": country,
                "asn": asn,
            }
        }
    }


@pytest.fixture
def vt_client():
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_vt_key", "ALIENVAULT_API_KEY": "test_otx_key"}):
        return VirusTotalClient()


# ------------------------------------------------------------------
# _parse_attributes
# ------------------------------------------------------------------

class TestParseAttributes:
    def test_basic_ip_parsing(self):
        data = _mock_vt_response(malicious=10, harmless=40, suspicious=5, undetected=45, country="RU", asn=12345)
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="ip", value="1.2.3.4")

        assert ioc.ioc_type == "ip"
        assert ioc.value == "1.2.3.4"
        assert ioc.malicious_votes == 10
        assert ioc.harmless_votes == 40
        assert ioc.suspicious_votes == 5
        assert ioc.undetected_votes == 45
        assert ioc.country == "RU"
        assert ioc.asn == "12345"
        assert "VirusTotal" in ioc.sources

    def test_threat_score_calculation(self):
        # 10 malicious out of 100 total → 10%
        data = _mock_vt_response(malicious=10, harmless=50, suspicious=10, undetected=30)
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="ip", value="x")
        assert abs(ioc.threat_score - 10.0) < 0.01

    def test_zero_total_gives_zero_score(self):
        data = _mock_vt_response(malicious=0, harmless=0, suspicious=0, undetected=0)
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="domain", value="clean.com")
        assert ioc.threat_score == 0.0

    def test_threat_labels_extracted(self):
        data = _mock_vt_response(labels=["Trojan.GenericKD", "Ransom.WannaCry"])
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="hash", value="abc123")
        assert "Trojan.GenericKD" in ioc.threat_labels
        assert "Ransom.WannaCry" in ioc.threat_labels

    def test_tags_propagated(self):
        data = _mock_vt_response(tags=["c2", "botnet"])
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="ip", value="5.5.5.5")
        assert "c2" in ioc.tags
        assert "botnet" in ioc.tags

    def test_last_analysis_date_formatted(self):
        data = _mock_vt_response(epoch=1700000000)
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="ip", value="x")
        assert ioc.last_analysis_date is not None
        assert "UTC" in ioc.last_analysis_date

    def test_missing_attributes_dont_crash(self):
        data = {"data": {"attributes": {}}}
        ioc = VirusTotalClient._parse_attributes(data, ioc_type="domain", value="empty.com")
        assert ioc.threat_score == 0.0
        assert ioc.country is None


# ------------------------------------------------------------------
# fetch_iocs — dispatch and error handling
# ------------------------------------------------------------------

class TestFetchIocs:
    def test_unsupported_type_raises(self, vt_client):
        with pytest.raises(ValueError, match="Unsupported IoC type"):
            vt_client.fetch_iocs("email", ["test@test.com"])

    def test_failed_request_is_logged_not_raised(self, vt_client):
        """A single bad response should be skipped, not crash everything."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = Exception("HTTP 404")
        vt_client._session.get = MagicMock(return_value=mock_resp)

        result = vt_client.fetch_iocs("ip", ["1.2.3.4"])
        assert result == []

    def test_batch_returns_multiple_iocs(self, vt_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _mock_vt_response(malicious=5)
        vt_client._session.get = MagicMock(return_value=mock_resp)

        result = vt_client.fetch_iocs("ip", ["1.2.3.4", "5.6.7.8"])
        assert len(result) == 2
        assert all(r.ioc_type == "ip" for r in result)

    def test_fetch_hash_calls_correct_endpoint(self, vt_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _mock_vt_response()
        vt_client._session.get = MagicMock(return_value=mock_resp)

        vt_client.fetch_iocs("hash", ["abc123"])
        call_url = vt_client._session.get.call_args[0][0]
        assert "/files/abc123" in call_url

    def test_fetch_url_base64_encodes(self, vt_client):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = _mock_vt_response()
        vt_client._session.get = MagicMock(return_value=mock_resp)

        vt_client.fetch_iocs("url", ["https://evil.com/path"])
        call_url = vt_client._session.get.call_args[0][0]
        assert "/urls/" in call_url
        # The original URL should NOT appear verbatim (it's base64-encoded)
        assert "https://evil.com/path" not in call_url
