"""
alienvault_client.py — Fetch IoC intelligence from the AlienVault OTX API v1.

Endpoints used:
  - /indicators/IPv4/{ip}/general
  - /indicators/domain/{domain}/general
  - /indicators/url/{url}/general
  - /indicators/file/{hash}/general
  - /pulses/subscribed            → latest pulses for bulk IoC extraction
"""

import logging
from typing import List, Optional
from urllib.parse import quote

import requests

from config import Config
from models import IoC

logger = logging.getLogger(__name__)

# OTX indicator type slugs
_TYPE_MAP = {
    "ip":     "IPv4",
    "domain": "domain",
    "url":    "url",
    "hash":   "file",
}


class AlienVaultClient:
    """Thin client for AlienVault OTX API v1."""

    def __init__(self) -> None:
        self._headers = {
            "X-OTX-API-KEY": Config.ALIENVAULT_API_KEY,
            "Accept": "application/json",
        }
        self._session = requests.Session()
        self._session.headers.update(self._headers)

    # ------------------------------------------------------------------
    # Public helpers — single indicator lookup
    # ------------------------------------------------------------------

    def fetch_ip(self, ip: str) -> IoC:
        data = self._get(f"/indicators/IPv4/{ip}/general")
        return self._parse_indicator(data, ioc_type="ip", value=ip)

    def fetch_domain(self, domain: str) -> IoC:
        data = self._get(f"/indicators/domain/{domain}/general")
        return self._parse_indicator(data, ioc_type="domain", value=domain)

    def fetch_url(self, url: str) -> IoC:
        encoded = quote(url, safe="")
        data = self._get(f"/indicators/url/{encoded}/general")
        return self._parse_indicator(data, ioc_type="url", value=url)

    def fetch_hash(self, file_hash: str) -> IoC:
        data = self._get(f"/indicators/file/{file_hash}/general")
        return self._parse_indicator(data, ioc_type="hash", value=file_hash)

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
                logger.warning("AlienVault: failed to fetch %s %r — %s", ioc_type, value, exc)
        return results

    # ------------------------------------------------------------------
    # Pulse-based bulk IoC extraction
    # ------------------------------------------------------------------

    def fetch_subscribed_pulses(self, limit: int = 5) -> List[IoC]:
        """
        Pull the most recent subscribed pulses and extract all IoCs from them.
        Returns a flat list of IoCs.
        """
        params = {"limit": limit}
        data = self._get("/pulses/subscribed", params=params)
        results: List[IoC] = []
        for pulse in data.get("results", []):
            pulse_name: str = pulse.get("name", "")
            tags: List[str] = pulse.get("tags", [])
            for indicator in pulse.get("indicators", []):
                ioc = self._parse_pulse_indicator(indicator, pulse_name, tags)
                if ioc:
                    results.append(ioc)
        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        url = Config.OTX_BASE_URL + path
        resp = self._session.get(url, params=params, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    @staticmethod
    def _parse_indicator(data: dict, ioc_type: str, value: str) -> IoC:
        pulse_info: dict = data.get("pulse_info", {})
        pulse_count: int = pulse_info.get("count", 0)

        # Aggregate tags from all pulses referencing this indicator
        tags: List[str] = []
        for pulse in pulse_info.get("pulses", []):
            tags.extend(pulse.get("tags", []))
        tags = sorted(set(tags))

        # Threat labels from pulse names (concise heuristic)
        threat_labels = sorted(
            {p.get("name", "") for p in pulse_info.get("pulses", []) if p.get("name")}
        )[:10]  # cap at 10

        # Simple threat score: log-scaled pulse count capped at 100
        import math
        threat_score = min(math.log1p(pulse_count) / math.log1p(200) * 100, 100.0)

        # Country / ASN
        country: Optional[str] = data.get("country_code") or data.get("country_name")
        asn: Optional[str] = data.get("asn")

        return IoC(
            ioc_type=ioc_type,
            value=value,
            threat_score=threat_score,
            threat_labels=threat_labels,
            tags=tags,
            sources=["AlienVault OTX"],
            country=country,
            asn=asn,
            pulse_count=pulse_count,
        )

    @staticmethod
    def _parse_pulse_indicator(indicator: dict, pulse_name: str, pulse_tags: List[str]) -> Optional[IoC]:
        """Map a single OTX pulse indicator record to an IoC object."""
        otx_type: str = indicator.get("type", "").lower()
        value: str = indicator.get("indicator", "")

        if not value:
            return None

        # Normalise OTX types to our canonical types
        type_map = {
            "ipv4":       "ip",
            "ipv6":       "ip",
            "domain":     "domain",
            "hostname":   "domain",
            "url":        "url",
            "filehash-md5":    "hash",
            "filehash-sha1":   "hash",
            "filehash-sha256": "hash",
        }
        ioc_type = type_map.get(otx_type)
        if not ioc_type:
            return None

        description: str = indicator.get("description", "") or pulse_name

        return IoC(
            ioc_type=ioc_type,
            value=value,
            tags=list(set(pulse_tags)),
            sources=["AlienVault OTX"],
            description=description,
            pulse_count=1,
        )
