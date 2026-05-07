"""
Shodan API collector for passive Smart City infrastructure discovery.

Strategy:
- Uses the official `shodan` Python SDK (not raw HTTP) for correct pagination
  via `search_cursor()` — a lazy generator that handles page tokens internally.
- Iterates over pre-defined dork queries from `dorks.py` for each target city.
- Enforces a per-query result cap (SHODAN_MAX_RESULTS_PER_QUERY) to prevent
  RAM exhaustion on large city queries.
- Enforces inter-request sleep to stay within Shodan's 1 req/sec rate limit.
- Raises ValueError if no API key is configured — no silent mock fallback.

Legal note: All data is fetched from Shodan's pre-scanned index.
Zero packets are sent directly to any target device.
"""

import logging
import time
from typing import Any

import shodan
import shodan.exception

from app.osint.base import BaseCollector
from app.osint.dorks import get_shodan_queries
from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Shodan enforces ~1 request/second for API plan users.
# We use 1.2s to add a small safety margin and avoid 429 errors.
_SHODAN_INTER_REQUEST_DELAY_SEC: float = 1.2
_SHODAN_BACKOFF_INITIAL_SEC: float = 30.0
_SHODAN_BACKOFF_MAX_SEC: float = 300.0
_SHODAN_MAX_RETRIES: int = 4


class ShodanCollector(BaseCollector):
    """
    Collect host and service data from the Shodan search index.

    This collector is city-centric: call `collect_for_city(city)` to run
    all dork queries for a single city. The `collect()` method is kept for
    backwards compatibility and direct domain-based lookups.
    """

    name = "shodan"

    def __init__(self) -> None:
        settings = get_settings()
        self.api_key = settings.SHODAN_API_KEY
        self.max_results = settings.SHODAN_MAX_RESULTS_PER_QUERY

        if not self.api_key:
            raise ValueError(
                "SHODAN_API_KEY is not configured. "
                "Set it in your .env file before running scans. "
                "Get a free key at https://account.shodan.io/"
            )

        # Initialise the official Shodan SDK client.
        self._api = shodan.Shodan(self.api_key)

    # ─── Public Interface ────────────────────────────────────────────────

    async def collect(self, target: str, **kwargs) -> list[dict[str, Any]]:
        """
        Legacy entrypoint: search Shodan by hostname/domain.

        For city-based Smart City scanning, prefer `collect_for_city()`.

        Args:
            target: Domain or hostname to query (e.g., "gov.kz").

        Returns:
            Normalized list of host dicts.
        """
        query = f'hostname:"{target}"'
        logger.info(f"[Shodan] Domain lookup: {query}")
        return self._execute_query(query, description=f"hostname:{target}")

    def collect_for_city(self, city: str) -> list[dict[str, Any]]:
        """
        Run all Smart City dork queries for a single city.

        Iterates over every query template in dorks.SHODAN_DORKS, substitutes
        the city name, fetches results with pagination, and deduplicates by IP.

        Args:
            city: City name as it appears in Shodan's geo index (e.g., "Almaty").

        Returns:
            Deduplicated list of normalized host dicts for the city.
        """
        queries = get_shodan_queries(city)
        logger.info(f"[Shodan] Starting city scan for '{city}' — {len(queries)} dork queries")

        # Use a dict keyed by IP to merge results from multiple queries.
        # If Shodan returns the same IP for two different dorks (e.g., both
        # port:554 and port:1883 match), we merge the services lists.
        merged_hosts: dict[str, dict] = {}

        for query_str, description in queries:
            logger.info(f"[Shodan] Query: {query_str!r} ({description})")
            try:
                results = self._execute_query_with_backoff(query_str, description=description)
                self._merge_into(merged_hosts, results)
                # Respect Shodan's rate limit between dork queries.
                time.sleep(_SHODAN_INTER_REQUEST_DELAY_SEC)
            except shodan.exception.APIError as exc:
                # Handle per-query errors gracefully — log and continue with
                # the next dork rather than aborting the entire city scan.
                if "No information available" in str(exc):
                    logger.info(f"[Shodan] No results for: {query_str!r}")
                elif "403" in str(exc):
                    logger.error(
                        f"[Shodan] Access Denied (403) for query {query_str!r}. "
                        "This usually means the filter (e.g., http.html, ssl.version) "
                        "requires a paid Shodan subscription."
                    )
                    break
                else:
                    logger.error(f"[Shodan] API error on query '{query_str}': {exc}")

        results_list = list(merged_hosts.values())
        logger.info(
            f"[Shodan] City '{city}' complete: {len(results_list)} unique hosts "
            f"from {len(queries)} queries"
        )
        return results_list

    # ─── Core Pagination Logic ───────────────────────────────────────────

    def _execute_query_with_backoff(
        self,
        query: str,
        description: str = "",
    ) -> list[dict[str, Any]]:
        delay = _SHODAN_BACKOFF_INITIAL_SEC

        for attempt in range(1, _SHODAN_MAX_RETRIES + 1):
            try:
                return self._execute_query(query, description=description)
            except shodan.exception.APIError as exc:
                if not self._is_rate_limit_error(exc) or attempt == _SHODAN_MAX_RETRIES:
                    raise

                logger.warning(
                    f"[Shodan] Rate limited on query {query!r} "
                    f"(attempt {attempt}/{_SHODAN_MAX_RETRIES}). "
                    f"Sleeping {delay:.0f}s before retry."
                )
                time.sleep(delay)
                delay = min(delay * 2, _SHODAN_BACKOFF_MAX_SEC)

        return []

    def _execute_query(self, query: str, description: str = "") -> list[dict[str, Any]]:
        """
        Execute a single Shodan query with pagination via search_cursor().

        `search_cursor()` is a generator that lazily fetches pages of results,
        handling internal page tokens automatically. We consume it until either:
        - The generator is exhausted (no more results), OR
        - We reach `self.max_results` to cap memory usage.

        Args:
            query: A complete Shodan search query string.
            description: Human-readable label for log messages.

        Returns:
            List of normalized host dicts.

        Raises:
            shodan.exception.APIError: For fatal API errors (e.g., invalid key).
        """
        results: list[dict[str, Any]] = []
        count = 0

        try:
            # search_cursor() is a generator — it does NOT load all results
            # into memory at once. Each iteration fetches the next page (100
            # results) from the Shodan API.
            cursor = self._api.search_cursor(query, minify=False)

            for match in cursor:
                if count >= self.max_results:
                    logger.debug(
                        f"[Shodan] Reached max_results cap ({self.max_results}) "
                        f"for query: {query!r}"
                    )
                    break

                normalized = self._normalize_match(match)
                if normalized:
                    results.append(normalized)
                    count += 1

        except shodan.exception.APIError as exc:
            error_msg = str(exc)
            # "No information available" is a normal Shodan response for
            # queries that return zero results — not an error condition.
            if "No information available" not in error_msg:
                raise  # Re-raise genuine errors to be handled by the caller.

        logger.debug(f"[Shodan] Query yielded {len(results)} hosts: {description}")
        return results

    @staticmethod
    def _is_rate_limit_error(exc: shodan.exception.APIError) -> bool:
        error_msg = str(exc).lower()
        return "rate limit" in error_msg or "429" in error_msg or "too many requests" in error_msg

    # ─── Result Normalization ────────────────────────────────────────────

    def _normalize_match(self, match: dict) -> dict[str, Any] | None:
        """
        Transform a raw Shodan match dict into the platform's standard format.

        Extracts IP, port, banner, geolocation, CPE, CVE, and product data.

        Args:
            match: A single result dict from Shodan's search API.

        Returns:
            Normalized host dict, or None if the match has no IP (skip it).
        """
        ip = match.get("ip_str", "")
        if not ip:
            return None

        port = match.get("port")
        transport = match.get("transport", "tcp")
        banner_raw = match.get("data", "")

        # Build the service entry from the Shodan match.
        service: dict[str, Any] = {
            "port": port,
            "protocol": transport,
            "service_name": match.get("product", match.get("_shodan", {}).get("module", "")),
            "banner_data": {
                # Truncate banners to 2000 chars to avoid DB bloat.
                "banner": banner_raw[:2000] if banner_raw else "",
                "product": match.get("product"),
                "version": match.get("version"),
                "os": match.get("os"),
                # CPE (Common Platform Enumeration) identifiers for the product.
                "cpe": match.get("cpe", []),
                # CVE IDs reported by Shodan for this specific host/port.
                "vulns": list(match.get("vulns", {}).keys()),
                # Raw Shodan module data (e.g., "rtsp", "ssh", "http").
                "shodan_module": match.get("_shodan", {}).get("module", ""),
                # HTTP-specific data if present.
                "http": match.get("http", {}),
                # SSL/TLS certificate data if present.
                "ssl": match.get("ssl", {}),
            },
        }

        location = match.get("location", {})
        geolocation: dict[str, Any] = {
            "lat": location.get("latitude"),
            "lon": location.get("longitude"),
            "city": location.get("city"),
            "country": location.get("country_name"),
            "country_code": location.get("country_code"),
            "region": location.get("area_code"),
            "asn": match.get("asn"),
            "org": match.get("org"),
            "isp": match.get("isp"),
        }

        return self._normalize_result(
            ip=ip,
            ports=[port] if port else [],
            hostnames=match.get("hostnames", []),
            geolocation=geolocation,
            services=[service],
            raw={
                "shodan_id": match.get("_shodan", {}).get("id"),
                "timestamp": match.get("timestamp"),
                "tags": match.get("tags", []),
                "domains": match.get("domains", []),
            },
        )

    # ─── Deduplication ───────────────────────────────────────────────────

    @staticmethod
    def _merge_into(
        host_map: dict[str, dict],
        new_results: list[dict[str, Any]],
    ) -> None:
        """
        Merge new results into an existing IP-keyed host map.

        If an IP already exists in the map (returned by a previous dork),
        we extend its services and hostnames lists rather than creating a
        duplicate host entry. This gives a complete per-host service picture.

        Args:
            host_map: Mutable dict mapping IP → normalized host dict.
            new_results: List of normalized host dicts to merge in.
        """
        for result in new_results:
            ip = result["ip_address"]
            if ip not in host_map:
                host_map[ip] = result
            else:
                # Extend rather than replace — preserve all services found
                # across multiple dork queries for the same IP.
                existing = host_map[ip]
                existing["services"].extend(result.get("services", []))
                # Union of hostnames (dedup happens later in the pipeline).
                existing_hostnames = set(existing.get("hostnames", []))
                existing_hostnames.update(result.get("hostnames", []))
                existing["hostnames"] = list(existing_hostnames)
                # Prefer the first geolocation we found (should be the same).
                if not existing.get("geolocation") and result.get("geolocation"):
                    existing["geolocation"] = result["geolocation"]
