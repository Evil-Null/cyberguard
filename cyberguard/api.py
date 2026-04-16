"""Threat intelligence API client."""
import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from cyberguard.config import Config
from cyberguard.constants import (
    CACHE_DIR, CACHE_TTL, MAX_RESULTS, RATE_LIMIT_DELAY, REQUEST_TIMEOUT, USER_AGENT,
)

_log = logging.getLogger("cyberguard")

class ThreatIntelAPI:
    """VirusTotal, AbuseIPDB, NVD API with rate-limiting and caching."""

    def __init__(self, config: Config):
        self.config = config
        self._last_request: Dict[str, float] = {}
        self._cache: Dict[str, Tuple[float, Any]] = {}

    def _rate_limit(self, service: str, delay: float = 1.0):
        last = self._last_request.get(service, 0)
        elapsed = time.time() - last
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request[service] = time.time()

    def _get_cached(self, key: str) -> Optional[Any]:
        if key in self._cache:
            ts, data = self._cache[key]
            if time.time() - ts < CACHE_TTL:
                return data
            del self._cache[key]
        return None

    def _set_cache(self, key: str, data: Any):
        self._cache[key] = (time.time(), data)

    # ── VirusTotal ──

    def vt_ip_reputation(self, ip: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        cache_key = f"vt_ip_{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("virustotal", 15.0)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def vt_hash_reputation(self, file_hash: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        cache_key = f"vt_hash_{file_hash}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("virustotal", 15.0)
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def vt_url_scan(self, url: str) -> dict:
        key = self.config.get_api_key("virustotal")
        if not key:
            raise ValueError("VirusTotal API key not configured")
        self._rate_limit("virustotal", 15.0)
        resp = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers={"x-apikey": key, "User-Agent": USER_AGENT},
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    # ── AbuseIPDB ──

    def abuseipdb_check(self, ip: str, max_age_days: int = 90) -> dict:
        key = self.config.get_api_key("abuseipdb")
        if not key:
            raise ValueError("AbuseIPDB API key not configured")
        cache_key = f"abuse_{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("abuseipdb", 1.0)
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    # ── NVD (National Vulnerability Database) ──

    def nvd_cve_lookup(self, cve_id: str) -> dict:
        cache_key = f"nvd_{cve_id}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached
        self._rate_limit("nvd", 0.6)
        headers = {"User-Agent": USER_AGENT}
        nvd_key = self.config.get_api_key("nvd")
        if nvd_key:
            headers["apiKey"] = nvd_key
        resp = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        self._set_cache(cache_key, data)
        return data

    def nvd_search(self, keyword: str, results_per_page: int = 20) -> dict:
        self._rate_limit("nvd", 0.6)
        headers = {"User-Agent": USER_AGENT}
        nvd_key = self.config.get_api_key("nvd")
        if nvd_key:
            headers["apiKey"] = nvd_key
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": results_per_page},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()


# ═══════════════════════════════════════════════════════════════════════════
# RESULT EXPORTER
# ═══════════════════════════════════════════════════════════════════════════
