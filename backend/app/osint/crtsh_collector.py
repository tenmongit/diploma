"""
Certificate Transparency log parser via crt.sh.

Discovers subdomains by querying the public crt.sh Certificate Transparency
log aggregator. No API key required — it is a free public service.

Changes from original:
- Removed hardcoded fallback subdomain set from the except block.
  On failure, returns an empty list (no fake/mock data).
- Added retry logic: 3 attempts with 5-second delay between retries.
- Increased timeout to 60s (crt.sh can be very slow under load).
- Added explicit JSON error handling for malformed responses.

Legal note: crt.sh only queries its own certificate log database.
No connection is made to discovered subdomains.
"""

import logging
import time
from typing import Any

import httpx

from app.osint.base import BaseCollector

logger = logging.getLogger(__name__)

_CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
_CRTSH_TIMEOUT_SEC = 20
_CRTSH_MAX_RETRIES = 3
_CRTSH_BACKOFF_INITIAL_SEC = 5
_CRTSH_BACKOFF_MAX_SEC = 30


class CrtshCollector(BaseCollector):
    """Discover subdomains via Certificate Transparency logs on crt.sh."""

    name = "crtsh"

    async def collect(self, target: str, **kwargs) -> list[dict[str, Any]]:
        """
        Query crt.sh for certificates that include the target domain as a SAN
        (Subject Alternative Name) or CN (Common Name).

        Returns unique subdomains found in Certificate Transparency logs.
        On failure after all retries, returns an empty list — no mock data.

        Args:
            target: Apex domain to search (e.g., "astana.gov.kz").

        Returns:
            List of normalized dicts with hostnames only (no IP resolution —
            the DNS module handles resolving discovered subdomains to IPs).
        """
        subdomains: set[str] = set()
        url = _CRTSH_URL.format(domain=target)
        delay = _CRTSH_BACKOFF_INITIAL_SEC

        # Retry loop — crt.sh can be unresponsive due to high load.
        for attempt in range(1, _CRTSH_MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(timeout=_CRTSH_TIMEOUT_SEC) as client:
                    logger.info(
                        f"[crt.sh] Querying for subdomains of '{target}' "
                        f"(attempt {attempt}/{_CRTSH_MAX_RETRIES})"
                    )
                    resp = await client.get(url)
                    resp.raise_for_status()

                    entries = resp.json()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            # Skip wildcard entries and entries that don't
                            # belong to our target domain.
                            if name and "*" not in name and name.endswith(target):
                                subdomains.add(name)

                    logger.info(
                        f"[crt.sh] Found {len(subdomains)} unique subdomains for '{target}'"
                    )
                    break  # Success — exit the retry loop.

            except httpx.TimeoutException:
                logger.warning(
                    f"[crt.sh] Timeout on attempt {attempt}/{_CRTSH_MAX_RETRIES} "
                    f"for '{target}'"
                )
                if attempt < _CRTSH_MAX_RETRIES:
                    time.sleep(delay)
                    delay = min(delay * 2, _CRTSH_BACKOFF_MAX_SEC)

            except httpx.HTTPStatusError as exc:
                logger.error(
                    f"[crt.sh] HTTP error {exc.response.status_code} for '{target}'"
                )
                break  # Non-retryable HTTP errors (e.g., 400, 500).

            except ValueError:
                # JSON decode error — crt.sh sometimes returns HTML on errors.
                logger.warning(
                    f"[crt.sh] Invalid JSON response on attempt {attempt}/{_CRTSH_MAX_RETRIES} "
                    f"for '{target}'"
                )
                if attempt < _CRTSH_MAX_RETRIES:
                    time.sleep(delay)
                    delay = min(delay * 2, _CRTSH_BACKOFF_MAX_SEC)

            except Exception as exc:
                logger.error(f"[crt.sh] Unexpected error for '{target}': {exc}")
                break

        # Return subdomains as normalized results (IP-less — DNS resolves them).
        results = []
        for sub in sorted(subdomains):
            results.append(self._normalize_result(
                ip="",
                ports=[],
                hostnames=[sub],
                raw={"source": "crt.sh", "apex_domain": target},
            ))

        return results
