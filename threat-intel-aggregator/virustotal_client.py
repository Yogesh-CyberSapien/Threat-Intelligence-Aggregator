"""
virustotal_client.py — Fetch IoC intelligence from the VirusTotal v3 API.

Supported IoC types:
  - ip        → /ip_addresses/{ip}
  - domain    → /domains/{domain}
  - url       → /urls/{url_id}   (URL must be base64url-encoded)
  - hash      → /files/{hash}    (MD5 / SHA-1 / SHA-256)
"""

import base64
import logging
from typing import List, Optional

import requests

from config import Config
from models import IoC

logger = logging.getLogger(__name__)


class VirusTotalClient:
    """Thin client for VirusTotal API v3."""

    def __init__(self) -> None:
        self._headers = {
            "x-apikey": Config.VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
        }
        self._session = requests.Session()
        self._session.headers.update(self._headers)

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def fetch_ip(self, ip: str) -> IoC:
        """Return an IoC for the given IP address."""
        data = self._get(f"/ip_addresses/{ip}")
        return self._parse_attributes(data, ioc_type="ip", value=ip)

    def fetch_domain(self, domain: str) -> IoC:
        """Return an IoC for the given domain."""
        data = self._get(f"/domains/{domain}")
        return self._parse_attributes(data, ioc_type="domain", value=domain)

    def fetch_url(self, url: str) -> IoC:
        """Return an IoC for the given URL."""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        data = self._get(f"/urls/{url_id}")
        return self._parse_attributes(data, ioc_type="url", value=url)

    def fetch_hash(self, file_hash: str) -> IoC:
        """Return an IoC for the given file hash (MD5/SHA-1/SHA-256)."""
        data = self._get(f"/files/{file_hash}")
        return self._parse_attributes(data, ioc_type="hash", value=file_hash)

    def fetch_iocs(self, ioc_type: str, values: List[str]) -> List[IoC]:
        """Batch-fetch IoCs by type and list of values."""
        dispatch = {
            "ip":     self.fetch_ip,
            "domain": self.fetch_domain,
            "url":    self.fetch_url,
            "hash":   self.fetch_hash,
        }
        if ioc_type not in dispatch:
            raise ValueError(f"Unsupported IoC type: {ioc_type!r}. Choose from: {list(dispatch)}")

        results: List[IoC] = []
        for value in values:
            try:
                ioc = dispatch[ioc_type](value)
                results.append(ioc)
            except Exception as exc:
                logger.warning("VirusTotal: failed to fetch %s %r — %s", ioc_type, value, exc)
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get(self, path: str) -> dict:
        url = Config.VT_BASE_URL + path
        resp = self._session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_attributes(data: dict, ioc_type: str, value: str) -> IoC:
        attrs = data.get("data", {}).get("attributes", {})

        # Last analysis stats
        stats: dict = attrs.get("last_analysis_stats", {})
        malicious    = stats.get("malicious", 0)
        harmless     = stats.get("harmless", 0)
        suspicious   = stats.get("suspicious", 0)
        undetected   = stats.get("undetected", 0)

        # Threat labels from last_analysis_results (engines that flagged it)
        analysis_results: dict = attrs.get("last_analysis_results", {})
        threat_labels = sorted(
            {
                res.get("result", "")
                for res in analysis_results.values()
                if res.get("category") == "malicious" and res.get("result")
            }
        )

        # Tags
        tags: List[str] = attrs.get("tags", [])

        # Normalise threat score: % of engines that flagged as malicious
        total = malicious + harmless + suspicious + undetected
        threat_score = (malicious / total * 100.0) if total else 0.0

        # Last analysis date (epoch → string)
        epoch = attrs.get("last_analysis_date")
        last_date: Optional[str] = None
        if epoch:
            from datetime import datetime, timezone
            last_date = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # Country / ASN (IP-specific)
        country = attrs.get("country")
        asn = str(attrs.get("asn", "")) or None

        return IoC(
            ioc_type=ioc_type,
            value=value,
            malicious_votes=malicious,
            harmless_votes=harmless,
            suspicious_votes=suspicious,
            undetected_votes=undetected,
            threat_score=threat_score,
            threat_labels=threat_labels,
            tags=tags,
            sources=["VirusTotal"],
            country=country,
            asn=asn,
            last_analysis_date=last_date,
        )
