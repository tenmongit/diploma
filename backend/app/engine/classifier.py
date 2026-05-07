"""
IF-THEN rule engine for classifying discovered services.

Rules map port + banner patterns to threat classifications
relevant to Smart City privacy analysis.
"""

import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Classification Rules ─────────────────────────────────────
# Each rule: (port_match, banner_pattern, classification, privacy_tags)
CLASSIFICATION_RULES = [
    # Surveillance devices
    (554, r"(?i)hikvision", "Surveillance Node", ["P:I", "P:L", "video_surveillance"]),
    (554, r"(?i)dahua", "Surveillance Node", ["P:I", "P:L", "video_surveillance"]),
    (554, r"(?i)rtsp", "Video Stream Endpoint", ["P:I", "video_stream"]),
    (554, r"(?i)axis", "Surveillance Node", ["P:I", "P:L", "video_surveillance"]),
    (554, r"(?i)vivotek", "Surveillance Node", ["P:I", "P:L", "video_surveillance"]),

    # IoT / Smart City
    (1883, r"(?i)mqtt", "IoT MQTT Broker", ["P:L", "iot_data"]),
    (8883, r"(?i)mqtt", "IoT MQTT Broker (TLS)", ["P:L", "iot_data"]),
    (502, r".*", "SCADA/Modbus Endpoint", ["P:NR", "industrial_control"]),
    (4840, r".*", "OPC-UA Server", ["P:NR", "industrial_control"]),

    # Web interfaces
    (80, r"(?i)hikvision|dahua|dvr|nvr", "Camera Web UI", ["P:I", "web_exposed"]),
    (80, r"(?i)sergek", "Sergek Dashboard", ["P:L", "traffic_monitoring"]),
    (80, r"(?i)iot[-_]?gateway", "IoT Gateway", ["P:L", "iot_data"]),
    (8080, r"(?i)iot[-_]?gateway", "IoT Gateway", ["P:L", "iot_data"]),
    (80, r"(?i)goahead", "Embedded Web Server", ["P:NR", "embedded_device"]),

    # Legacy / insecure protocols
    (23, r".*", "Telnet Service (Insecure)", ["P:L", "P:I", "legacy_protocol"]),
    (21, r".*", "FTP Service (Insecure)", ["P:I", "legacy_protocol"]),
    (161, r".*", "SNMP Service", ["P:L", "network_monitoring"]),

    # TLS issues
    (443, r"(?i)tls.*1\.0|ssl.*3", "Weak TLS Configuration", ["P:I", "weak_crypto"]),
    (8443, r"(?i)self[_-]?signed", "Self-Signed Certificate", ["P:I", "weak_crypto"]),

    # General web
    (443, r".*", "HTTPS Service", []),
    (80, r".*", "HTTP Service", []),
    (8080, r".*", "HTTP-Proxy Service", []),
]


def classify_service(port: int, banner: str, product: str = "") -> dict:
    """
    Classify a service based on its port and banner.

    Returns:
        {
            "classification": str,
            "privacy_tags": list[str],
            "matched_rule": str,
        }
    """
    combined_text = f"{banner} {product}".strip()

    for rule_port, pattern, classification, tags in CLASSIFICATION_RULES:
        if rule_port == port:
            if re.search(pattern, combined_text):
                logger.debug(f"Classified port {port} as '{classification}'")
                return {
                    "classification": classification,
                    "privacy_tags": tags,
                    "matched_rule": f"port={rule_port}, pattern={pattern}",
                }

    # Default fallback
    return {
        "classification": f"Service on port {port}",
        "privacy_tags": [],
        "matched_rule": "default",
    }


def classify_host_services(services: list[dict]) -> list[dict]:
    """
    Classify all services on a host.

    Args:
        services: List of dicts with 'port', 'banner_data' keys.

    Returns:
        List of services with added 'classification' and 'privacy_tags'.
    """
    classified = []
    for svc in services:
        port = svc.get("port", 0)
        banner_data = svc.get("banner_data", {})
        banner = banner_data.get("banner", "") if isinstance(banner_data, dict) else ""
        product = banner_data.get("product", "") if isinstance(banner_data, dict) else ""

        result = classify_service(port, banner, product)
        svc["classification"] = result["classification"]
        svc["privacy_tags"] = result["privacy_tags"]
        classified.append(svc)

    return classified
