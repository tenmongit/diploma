"""
Centralized OSINT dork definitions for Smart City infrastructure discovery.

This module is the single source of truth for all Shodan and Censys search
queries. Dorks are defined as format-string templates where {city} is
substituted with a city name at runtime.

Design principle: Dorks are *data*, not code. Adding a new search pattern
requires only adding a new string here — no changes to collector logic.

All queries are passive (read-only against third-party APIs).
No packets are sent directly to discovered hosts.
"""

from dataclasses import dataclass, field
from typing import Final


# ─── Kazakhstan Smart City Target List ──────────────────────────────────────

@dataclass(frozen=True)
class City:
    """Metadata for a target city."""
    name: str           # Primary name used in API dorks (English)
    country: str = "Kazakhstan"
    country_code: str = "KZ"
    # Alternative spellings / transliterations that may appear in Shodan data
    aliases: list[str] = field(default_factory=list)


KAZAKHSTAN_CITIES: Final[list[City]] = [
    City(name="Almaty",    aliases=["Alma-Ata", "Алматы"]),
    City(name="Astana",    aliases=["Nur-Sultan", "Нур-Султан", "Астана"]),
    City(name="Shymkent",  aliases=["Chimkent", "Шымкент"]),
    City(name="Karaganda", aliases=["Qaraghandy", "Қарағанды"]),
    City(name="Aktobe",    aliases=["Aktöbe", "Актобе"]),
    City(name="Atyrau",    aliases=["Гурьев", "Атырау"]),
    City(name="Pavlodar",  aliases=["Павлодар"]),
    City(name="Semey",     aliases=["Semipalatinsk", "Семей"]),
]


# ─── Shodan Dork Templates ───────────────────────────────────────────────────

# Each entry is a tuple of (query_template, description).
# Use {city} as the placeholder for the city name.
# These queries map to known Smart City device categories.

SHODAN_DORKS: Final[list[tuple[str, str]]] = [
    # ── Free Tier Compatible Queries ────────────────────────────────────
    # Shodan free tier does not support port filters, product filters, or
    # location filters. Use domain-based queries only.
    # These queries target the specific domain being scanned.
    (
        'hostname:{domain}',
        "Hosts matching target domain (free tier compatible)",
    ),
]


# ─── Censys Dork Templates ───────────────────────────────────────────────────

# Censys v2 API uses Lucene-style query syntax.
# `location.city` and `location.country` are indexed fields.
# `services.port` and `services.service_name` for service-level matching.

CENSYS_DORKS: Final[list[tuple[str, str]]] = [
    # ── Surveillance Cameras ─────────────────────────────────────────────
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.port=554',
        "RTSP endpoints (surveillance cameras)",
    ),
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.banner: "Hikvision"',
        "Hikvision devices (banner-based detection)",
    ),
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.banner: "Dahua"',
        "Dahua devices (banner-based detection)",
    ),

    # ── IoT / MQTT ───────────────────────────────────────────────────────
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.port=1883',
        "Unencrypted MQTT brokers",
    ),

    # ── SCADA / Industrial ───────────────────────────────────────────────
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.port=502',
        "Modbus TCP endpoints",
    ),
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.port=4840',
        "OPC-UA servers",
    ),

    # ── Weak TLS ─────────────────────────────────────────────────────────
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.tls.certificates.leaf_data.issuer.common_name: "Self Signed"',
        "Self-signed certificates",
    ),

    # ── Insecure Protocols ───────────────────────────────────────────────
    (
        'location.city="{city}" AND location.country="Kazakhstan" AND services.port=23',
        "Telnet services",
    ),
]


def get_shodan_queries(city: str) -> list[tuple[str, str]]:
    """
    Generate all Shodan queries for a given city name.

    Args:
        city: City name to substitute into dork templates (e.g., "Almaty").

    Returns:
        List of (query_string, description) tuples ready to send to Shodan.
    """
    return [
        (template.format(city=city), description)
        for template, description in SHODAN_DORKS
    ]


def get_censys_queries(city: str) -> list[tuple[str, str]]:
    """
    Generate all Censys queries for a given city name.

    Args:
        city: City name to substitute into dork templates.

    Returns:
        List of (query_string, description) tuples ready to send to Censys.
    """
    return [
        (template.format(city=city), description)
        for template, description in CENSYS_DORKS
    ]
