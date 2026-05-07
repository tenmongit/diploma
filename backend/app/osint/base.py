"""Abstract base class for all OSINT collectors."""

from abc import ABC, abstractmethod
from typing import Any
import logging

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base interface for OSINT data collectors."""

    name: str = "base"

    @abstractmethod
    async def collect(self, target: str, **kwargs) -> list[dict[str, Any]]:
        """
        Collect data for the given target.

        Args:
            target: Domain, IP, or search query depending on the collector.

        Returns:
            List of normalized result dicts with at minimum:
            - ip_address: str
            - ports: list[int]
            - hostnames: list[str]
            - data: dict (raw/enriched data)
        """
        ...

    def _normalize_result(
        self,
        ip: str,
        ports: list[int] = None,
        hostnames: list[str] = None,
        geolocation: dict = None,
        services: list[dict] = None,
        raw: dict = None,
    ) -> dict:
        """Normalize collector output into a standard format."""
        return {
            "source": self.name,
            "ip_address": ip,
            "ports": ports or [],
            "hostnames": hostnames or [],
            "geolocation": geolocation or {},
            "services": services or [],
            "raw": raw or {},
        }
