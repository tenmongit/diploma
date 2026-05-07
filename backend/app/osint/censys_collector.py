"""
Censys API collector for passive Smart City infrastructure discovery.

Strategy:
- Uses the official `censys` Python SDK (v2) which provides proper cursor-based
  pagination via `CensysHosts.search()` — a generator that lazily fetches pages.
- Iterates over pre-defined dork queries from `dorks.py` for each target city.
- Caps page count at CENSYS_MAX_PAGES to prevent RAM exhaustion.
- Enforces inter-request sleep to respect Censys free tier rate limits
  (~0.4 req/sec = max 1 request every 2.5 seconds).
- Raises ValueError if API credentials are missing — no silent mock fallback.

Legal note: All data is fetched from Censys's pre-scanned index.
Zero packets are sent directly to any target device.
"""

import logging
import time
from typing import Any

import httpx
from censys.search import CensysHosts
from censys.common.exceptions import (
    CensysRateLimitExceededException,
    CensysUnauthorizedException,
    CensysNotFoundException,
    CensysException,
)

from app.osint.base import BaseCollector
from app.osint.dorks import get_censys_queries
from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Censys free tier: 0.4 requests/second = 1 request per 2.5 seconds.
# We use 3.0s to add a safety margin and avoid 429 errors.
_CENSYS_INTER_REQUEST_DELAY_SEC: float = 3.0
_CENSYS_BACKOFF_INITIAL_SEC: float = 30.0
_CENSYS_BACKOFF_MAX_SEC: float = 300.0
_CENSYS_MAX_RETRIES: int = 4

# Censys returns up to 100 hosts per page.
_CENSYS_PAGE_SIZE: int = 100
_CENSYS_PLATFORM_SEARCH_URL = "https://api.platform.censys.io/v3/global/search/query"


class CensysCollector(BaseCollector):
    """
    Collect host and TLS certificate data from the Censys search index.

    This collector is city-centric: call `collect_for_city(city)` to run
    all dork queries for a single city. The `collect()` method is kept for
    backwards compatibility and domain-based lookups.
    """

    name = "censys"

    def __init__(self) -> None:
        settings = get_settings()
        self.api_id = settings.CENSYS_API_ID
        self.api_secret = settings.CENSYS_API_SECRET
        self.api_key = settings.CENSYS_API_KEY  # Personal Access Token (PAT)
        self.org_id = settings.CENSYS_ORG_ID
        self.max_pages = settings.CENSYS_MAX_PAGES

        self._use_platform_api = bool(self.api_key and not (self.api_id and self.api_secret))

        if not self._use_platform_api and (not self.api_id or not self.api_secret):
            raise ValueError(
                "Censys authentication is not configured correctly. "
                "Set CENSYS_API_KEY or CENSYS_API_ID and CENSYS_API_SECRET in your .env file."
            )

        if self._use_platform_api:
            logger.info("[Censys] Initializing with Platform API Personal Access Token")
            self._api = None
        else:
            logger.info("[Censys] Initializing with legacy API ID and Secret")
            self._api = CensysHosts(api_id=self.api_id, api_secret=self.api_secret)

    # ─── Public Interface ────────────────────────────────────────────────

    async def collect(self, target: str, **kwargs) -> list[dict[str, Any]]:
        """
        Legacy entrypoint: search Censys by domain name.

        For city-based Smart City scanning, prefer `collect_for_city()`.

        Args:
            target: Domain to query (e.g., "gov.kz").

        Returns:
            Normalized list of host dicts.
        """
        query = f'dns.names: "{target}"'
        logger.info(f"[Censys] Domain lookup: {query}")
        return self._execute_query(query, description=f"dns.names:{target}")

    def collect_for_city(self, city: str) -> list[dict[str, Any]]:
        """
        Run all Smart City dork queries for a single city.

        Iterates over every query template in dorks.CENSYS_DORKS, substitutes
        the city name, fetches results with cursor-based pagination, and
        deduplicates by IP address.

        Args:
            city: City name matching Censys's location.city index (e.g., "Almaty").

        Returns:
            Deduplicated list of normalized host dicts for the city.
        """
        queries = get_censys_queries(city)
        logger.info(f"[Censys] Starting city scan for '{city}' — {len(queries)} dork queries")

        # IP-keyed map for deduplication across multiple dork queries.
        merged_hosts: dict[str, dict] = {}

        for query_str, description in queries:
            logger.info(f"[Censys] Query: {query_str!r} ({description})")
            try:
                results = self._execute_query_with_backoff(query_str, description=description)
                self._merge_into(merged_hosts, results)
                # Respect Censys rate limits between queries.
                time.sleep(_CENSYS_INTER_REQUEST_DELAY_SEC)

            except CensysUnauthorizedException:
                # Invalid credentials — abort all further queries immediately.
                logger.error(
                    "[Censys] Authentication failed. Check CENSYS_API_KEY or "
                    "CENSYS_API_ID and CENSYS_API_SECRET in your .env file."
                )
                raise

            except httpx.HTTPStatusError as exc:
                logger.error(
                    f"[Censys] HTTP {exc.response.status_code} on query '{query_str}': "
                    f"{exc.response.text[:500]}"
                )
                if exc.response.status_code in (401, 403):
                    break

            except CensysNotFoundException:
                logger.info(f"[Censys] No results for: {query_str!r}")

            except CensysException as exc:
                logger.error(f"[Censys] API error on query '{query_str}': {exc}")

        results_list = list(merged_hosts.values())
        logger.info(
            f"[Censys] City '{city}' complete: {len(results_list)} unique hosts "
            f"from {len(queries)} queries"
        )
        return results_list

    # ─── Core Pagination Logic ───────────────────────────────────────────

    def _execute_query_with_backoff(
        self,
        query: str,
        description: str = "",
    ) -> list[dict[str, Any]]:
        delay = _CENSYS_BACKOFF_INITIAL_SEC

        for attempt in range(1, _CENSYS_MAX_RETRIES + 1):
            try:
                return self._execute_query(query, description=description)
            except CensysRateLimitExceededException:
                if attempt == _CENSYS_MAX_RETRIES:
                    raise

                logger.warning(
                    f"[Censys] Rate limited on query {query!r} "
                    f"(attempt {attempt}/{_CENSYS_MAX_RETRIES}). "
                    f"Sleeping {delay:.0f}s before retry."
                )
                time.sleep(delay)
                delay = min(delay * 2, _CENSYS_BACKOFF_MAX_SEC)
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code != 429 or attempt == _CENSYS_MAX_RETRIES:
                    raise

                logger.warning(
                    f"[Censys] HTTP 429 on query {query!r} "
                    f"(attempt {attempt}/{_CENSYS_MAX_RETRIES}). "
                    f"Sleeping {delay:.0f}s before retry."
                )
                time.sleep(delay)
                delay = min(delay * 2, _CENSYS_BACKOFF_MAX_SEC)

        return []

    def _execute_query(self, query: str, description: str = "") -> list[dict[str, Any]]:
        """
        Execute a single Censys query with cursor-based pagination.

        The Censys SDK's `search()` method returns a generator (SearchResults)
        that lazily fetches pages of up to 100 hosts each. We iterate page by
        page until either the generator is exhausted or we reach `max_pages`.

        Args:
            query: A complete Censys search query string.
            description: Human-readable label for log messages.

        Returns:
            Normalized list of host dicts.

        Raises:
            CensysUnauthorizedException: If API credentials are invalid.
            CensysRateLimitExceededException: If rate limit is exceeded.
        """
        if self._use_platform_api:
            return self._execute_platform_query(query, description=description)

        results: list[dict[str, Any]] = []
        page_num = 0

        # CensysHosts.search() returns a SearchResults generator.
        # Calling list() on it would load ALL pages — we iterate manually
        # to enforce our max_pages cap.
        search_results = self._api.search(
            query=query,
            per_page=_CENSYS_PAGE_SIZE,
            # The fields we want Censys to return per host.
            # Fewer fields = faster responses and smaller payloads.
            fields=[
                "ip",
                "services.port",
                "services.transport_protocol",
                "services.service_name",
                "services.banner",
                "services.software",
                "services.tls",
                "location.city",
                "location.country",
                "location.coordinates",
                "autonomous_system.asn",
                "autonomous_system.name",
                "dns.names",
            ],
        )

        for page in search_results.pages():
            if page_num >= self.max_pages:
                logger.debug(
                    f"[Censys] Reached max_pages cap ({self.max_pages}) "
                    f"for query: {query!r}"
                )
                break

            page_num += 1
            logger.debug(
                f"[Censys] Page {page_num}/{self.max_pages} "
                f"({len(page)} hosts) for: {description}"
            )

            for hit in page:
                normalized = self._normalize_hit(hit)
                if normalized:
                    results.append(normalized)

            # Sleep between pages to respect the rate limit.
            if page_num < self.max_pages:
                time.sleep(_CENSYS_INTER_REQUEST_DELAY_SEC)

        logger.debug(f"[Censys] Query yielded {len(results)} hosts: {description}")
        return results

    def _execute_platform_query(self, query: str, description: str = "") -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page_num = 0
        page_token = None
        platform_query = self._to_platform_query(query)
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        with httpx.Client(timeout=60) as client:
            while page_num < self.max_pages:
                payload: dict[str, Any] = {
                    "query": platform_query,
                    "per_page": _CENSYS_PAGE_SIZE,
                    "fields": [
                        "host.ip",
                        "host.names",
                        "host.services.port",
                        "host.services.transport_protocol",
                        "host.services.protocol",
                        "host.services.service_name",
                        "host.services.banner",
                        "host.location.city",
                        "host.location.country",
                        "host.location.country_code",
                        "host.location.coordinates",
                        "host.autonomous_system.asn",
                        "host.autonomous_system.name",
                    ],
                }
                if page_token:
                    payload["page_token"] = page_token
                if self.org_id:
                    payload["organization_id"] = self.org_id

                response = client.post(_CENSYS_PLATFORM_SEARCH_URL, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                result = data.get("result", data)
                hits = (
                    result.get("hits")
                    or result.get("records")
                    or result.get("results")
                    or data.get("hits")
                    or []
                )

                page_num += 1
                logger.debug(
                    f"[Censys] Platform page {page_num}/{self.max_pages} "
                    f"({len(hits)} hosts) for: {description}"
                )

                for hit in hits:
                    normalized = self._normalize_platform_hit(hit)
                    if normalized:
                        results.append(normalized)

                page_token = self._extract_next_page_token(result)
                if not page_token:
                    break

                time.sleep(_CENSYS_INTER_REQUEST_DELAY_SEC)

        logger.debug(f"[Censys] Platform query yielded {len(results)} hosts: {description}")
        return results

    @staticmethod
    def _to_platform_query(query: str) -> str:
        return (
            query
            .replace("location.city=", "host.location.city: ")
            .replace("location.country=", "host.location.country: ")
            .replace("services.port=", "host.services.port: ")
            .replace("services.banner:", "host.services.banner:")
            .replace(
                "services.tls.certificates.leaf_data.issuer.common_name:",
                "host.services.tls.certificates.leaf_data.issuer.common_name:",
            )
        )

    @staticmethod
    def _extract_next_page_token(result: dict[str, Any]) -> str | None:
        links = result.get("links", {})
        pagination = result.get("pagination", {})
        return (
            result.get("next_page_token")
            or result.get("next")
            or links.get("next")
            or pagination.get("next_page_token")
            or pagination.get("next")
        )

    # ─── Result Normalization ────────────────────────────────────────────

    def _normalize_hit(self, hit: dict) -> dict[str, Any] | None:
        """
        Transform a raw Censys hit dict into the platform's standard format.

        Args:
            hit: A single result dict from Censys's hosts search.

        Returns:
            Normalized host dict, or None if the hit has no IP.
        """
        ip = hit.get("ip", "")
        if not ip:
            return None

        services: list[dict[str, Any]] = []
        ports: list[int] = []

        for svc in hit.get("services", []):
            port = svc.get("port")
            if port:
                ports.append(port)

            tls_data = svc.get("tls", {})
            cert_data = tls_data.get("certificates", {}).get("leaf_data", {})

            services.append({
                "port": port,
                "protocol": svc.get("transport_protocol", "TCP").lower(),
                "service_name": svc.get("service_name", ""),
                "banner_data": {
                    "banner": (svc.get("banner") or "")[:2000],
                    "software": svc.get("software", []),
                    # TLS/SSL certificate details — critical for detecting
                    # weak crypto and self-signed certificates.
                    "certificate": {
                        "issuer": cert_data.get("issuer", {}).get("common_name", ""),
                        "subject": cert_data.get("subject", {}).get("common_name", ""),
                        "not_before": cert_data.get("validity", {}).get("start", ""),
                        "not_after": cert_data.get("validity", {}).get("end", ""),
                        "fingerprint_sha256": cert_data.get("fingerprint", {}).get("sha256", ""),
                        "self_signed": cert_data.get("is_self_signed", False),
                    },
                    "tls_version": tls_data.get("version_selected", ""),
                    "cipher_suite": tls_data.get("cipher_selected", ""),
                },
            })

        location = hit.get("location", {})
        coordinates = location.get("coordinates", {})
        asn_info = hit.get("autonomous_system", {})

        geolocation: dict[str, Any] = {
            "lat": coordinates.get("latitude"),
            "lon": coordinates.get("longitude"),
            "city": location.get("city"),
            "country": location.get("country"),
            "country_code": location.get("country_code"),
            "asn": asn_info.get("asn"),
            "org": asn_info.get("name"),
        }

        return self._normalize_result(
            ip=ip,
            ports=ports,
            hostnames=hit.get("dns", {}).get("names", []),
            geolocation=geolocation,
            services=services,
            raw={"autonomous_system": asn_info},
        )

    def _normalize_platform_hit(self, hit: dict[str, Any]) -> dict[str, Any] | None:
        host = hit.get("host", hit)
        ip = host.get("ip") or host.get("ip_address") or hit.get("ip") or hit.get("host_identifier")
        if not ip:
            return None

        raw_services = (
            hit.get("matched_services")
            or host.get("matched_services")
            or host.get("services")
            or hit.get("services")
            or []
        )
        services: list[dict[str, Any]] = []
        ports: list[int] = []

        for svc in raw_services:
            port = svc.get("port")
            if port:
                ports.append(port)

            services.append({
                "port": port,
                "protocol": (
                    svc.get("transport_protocol")
                    or svc.get("protocol")
                    or "tcp"
                ).lower(),
                "service_name": svc.get("service_name", ""),
                "banner_data": {
                    "banner": (svc.get("banner") or "")[:2000],
                    "software": svc.get("software", []),
                    "tls": svc.get("tls", {}),
                },
            })

        location = host.get("location", hit.get("location", {}))
        coordinates = location.get("coordinates") or {}
        asn_info = host.get("autonomous_system", hit.get("autonomous_system", {}))
        names = host.get("names") or hit.get("names") or host.get("dns", {}).get("names", [])

        geolocation: dict[str, Any] = {
            "lat": coordinates.get("latitude") or coordinates.get("lat"),
            "lon": coordinates.get("longitude") or coordinates.get("lon"),
            "city": location.get("city"),
            "country": location.get("country"),
            "country_code": location.get("country_code"),
            "asn": asn_info.get("asn"),
            "org": asn_info.get("name"),
        }

        return self._normalize_result(
            ip=ip,
            ports=ports,
            hostnames=names if isinstance(names, list) else [],
            geolocation=geolocation,
            services=services,
            raw={"autonomous_system": asn_info},
        )

    # ─── Deduplication ───────────────────────────────────────────────────

    @staticmethod
    def _merge_into(
        host_map: dict[str, dict],
        new_results: list[dict[str, Any]],
    ) -> None:
        """
        Merge new results into an existing IP-keyed host map.

        Prevents duplicate host entries when the same IP matches multiple
        dork queries (e.g., both port:554 and ssl queries).

        Args:
            host_map: Mutable dict mapping IP → normalized host dict.
            new_results: List of normalized host dicts to merge in.
        """
        for result in new_results:
            ip = result["ip_address"]
            if ip not in host_map:
                host_map[ip] = result
            else:
                existing = host_map[ip]
                existing["services"].extend(result.get("services", []))
                existing_hostnames = set(existing.get("hostnames", []))
                existing_hostnames.update(result.get("hostnames", []))
                existing["hostnames"] = list(existing_hostnames)
                if not existing.get("geolocation") and result.get("geolocation"):
                    existing["geolocation"] = result["geolocation"]
