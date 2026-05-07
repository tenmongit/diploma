"""
Risk scoring engine using modified CVSSv4.0 + LINDDUN privacy model.

Produces a composite risk score (0.0 - 10.0) and severity label,
incorporating both traditional vulnerability metrics and
privacy-specific factors.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── LINDDUN Privacy Threat Categories ──────────────────────
LINDDUN_CATEGORIES = {
    "L": "Linkability",
    "I": "Identifiability",
    "NR": "Non-Repudiation",
    "D": "Detectability",
    "DI": "Disclosure of Information",
    "UC": "Unawareness/Uncontrollability",
    "NC": "Non-Compliance",
}


# ── Port Risk Weights ─────────────────────────────────────
PORT_RISK = {
    23: 3.0,     # Telnet — plaintext
    21: 2.5,     # FTP — plaintext
    554: 2.5,    # RTSP — video stream
    502: 3.0,    # Modbus — no auth
    4840: 2.5,   # OPC-UA
    1883: 2.0,   # MQTT — no TLS
    161: 1.5,    # SNMP
    80: 1.0,     # HTTP
    8080: 1.0,   # HTTP-alt
    443: 0.5,    # HTTPS
    8443: 0.5,   # HTTPS-alt
    8883: 0.5,   # MQTT-TLS
}

# ── Privacy Tag Weights ───────────────────────────────────
PRIVACY_WEIGHTS = {
    "P:I": 2.0,           # Identifiability
    "P:L": 1.5,           # Linkability
    "P:NR": 1.0,          # Non-Repudiation
    "video_surveillance": 2.5,
    "video_stream": 2.0,
    "iot_data": 1.0,
    "traffic_monitoring": 1.5,
    "legacy_protocol": 1.5,
    "weak_crypto": 1.5,
    "web_exposed": 0.5,
    "industrial_control": 2.0,
    "network_monitoring": 0.5,
    "embedded_device": 1.0,
}

# ── Banner keywords indicating PII exposure ──────────────
PII_INDICATORS = [
    "personal", "pii", "name", "email", "phone", "passport",
    "iin", "address", "biometric", "face", "recognition",
    "license plate", "tracking", "location data",
]

# ── Known vulnerable products ─────────────────────────────
VULNERABLE_PRODUCTS = {
    "hikvision": {"base_vuln_score": 3.0, "cves": ["CVE-2021-36260", "CVE-2017-7921"]},
    "dahua": {"base_vuln_score": 2.5, "cves": ["CVE-2021-33044", "CVE-2020-25078"]},
    "goahead": {"base_vuln_score": 2.0, "cves": ["CVE-2017-17562"]},
    "mosquitto": {"base_vuln_score": 1.0, "cves": []},
    "sergek": {"base_vuln_score": 1.5, "cves": []},
}


def calculate_risk_score(
    port: int,
    banner: str = "",
    product: str = "",
    privacy_tags: list[str] = None,
    classification: str = "",
    tls_version: str = "",
) -> dict:
    """
    Calculate a composite risk score using CVSSv4.0 base + LINDDUN privacy factors.

    Returns:
        {
            "risk_score": float (0-10),
            "severity": str (Low/Medium/High/Critical),
            "breakdown": {
                "port_exposure": float,
                "protocol_security": float,
                "software_risk": float,
                "privacy_impact": float,
                "pii_detected": bool,
            },
            "privacy_metrics": {
                "P:L": float,
                "P:I": float,
                "P:NR": float,
            },
            "associated_cves": list[str],
            "linddun_threats": list[str],
        }
    """
    privacy_tags = privacy_tags or []
    banner_lower = banner.lower()
    product_lower = product.lower()
    combined = f"{banner_lower} {product_lower} {classification.lower()}"

    # 1. Port Exposure Score (0-3)
    port_score = PORT_RISK.get(port, 0.5)

    # 2. Protocol Security Score (0-2)
    protocol_score = 0.0
    if port in (23, 21):  # Plaintext protocols
        protocol_score = 2.0
    elif port == 1883:  # MQTT without TLS
        protocol_score = 1.5
    elif port == 502:  # Modbus — no auth
        protocol_score = 2.0
    elif tls_version:
        if "1.0" in tls_version or "ssl" in tls_version.lower():
            protocol_score = 1.5
        elif "1.1" in tls_version:
            protocol_score = 1.0
        elif "1.2" in tls_version:
            protocol_score = 0.3
        else:
            protocol_score = 0.0

    # 3. Software Vulnerability Score (0-3)
    software_score = 0.0
    associated_cves = []
    for prod_name, prod_info in VULNERABLE_PRODUCTS.items():
        if prod_name in combined:
            software_score = max(software_score, prod_info["base_vuln_score"])
            associated_cves.extend(prod_info["cves"])

    # 4. Privacy Impact Score (0-4)
    privacy_score = 0.0
    privacy_metrics = {"P:L": 0.0, "P:I": 0.0, "P:NR": 0.0}
    linddun_threats = []

    for tag in privacy_tags:
        weight = PRIVACY_WEIGHTS.get(tag, 0.0)
        privacy_score += weight

        # Map to LINDDUN metrics
        if tag == "P:L" or tag in ("video_surveillance", "traffic_monitoring", "iot_data"):
            privacy_metrics["P:L"] = min(privacy_metrics["P:L"] + weight, 4.0)
            if "Linkability" not in linddun_threats:
                linddun_threats.append("Linkability")
        if tag == "P:I" or tag in ("video_surveillance", "video_stream", "legacy_protocol"):
            privacy_metrics["P:I"] = min(privacy_metrics["P:I"] + weight, 4.0)
            if "Identifiability" not in linddun_threats:
                linddun_threats.append("Identifiability")
        if tag == "P:NR" or tag in ("industrial_control",):
            privacy_metrics["P:NR"] = min(privacy_metrics["P:NR"] + weight, 4.0)
            if "Non-Repudiation" not in linddun_threats:
                linddun_threats.append("Non-Repudiation")

    privacy_score = min(privacy_score, 4.0)

    # 5. PII Detection — auto-escalate
    pii_detected = any(indicator in combined for indicator in PII_INDICATORS)
    pii_bonus = 3.0 if pii_detected else 0.0

    # ── Composite Score ──────────────────────────────────
    # Weighted sum normalized to 0-10
    raw_score = port_score + protocol_score + software_score + privacy_score + pii_bonus
    risk_score = min(round(raw_score, 1), 10.0)

    # Severity classification
    if risk_score >= 9.0 or pii_detected:
        severity = "critical"
    elif risk_score >= 7.0:
        severity = "high"
    elif risk_score >= 4.0:
        severity = "medium"
    else:
        severity = "low"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "breakdown": {
            "port_exposure": port_score,
            "protocol_security": protocol_score,
            "software_risk": software_score,
            "privacy_impact": privacy_score,
            "pii_detected": pii_detected,
        },
        "privacy_metrics": privacy_metrics,
        "associated_cves": list(set(associated_cves)),
        "linddun_threats": linddun_threats,
    }


def score_host(services: list[dict]) -> dict:
    """
    Calculate aggregate risk score for a host across all its services.

    Returns the highest individual score and aggregated threat data.
    """
    if not services:
        return {
            "risk_score": 0.0,
            "severity": "low",
            "all_cves": [],
            "all_threats": [],
            "service_scores": [],
        }

    service_scores = []
    all_cves = set()
    all_threats = set()

    for svc in services:
        port = svc.get("port", 0)
        banner_data = svc.get("banner_data", {})
        banner = banner_data.get("banner", "") if isinstance(banner_data, dict) else ""
        product = banner_data.get("product", "") if isinstance(banner_data, dict) else ""
        tls = banner_data.get("tls", {}) if isinstance(banner_data, dict) else {}
        tls_version = tls.get("version", "") if isinstance(tls, dict) else ""

        result = calculate_risk_score(
            port=port,
            banner=banner,
            product=product,
            privacy_tags=svc.get("privacy_tags", []),
            classification=svc.get("classification", ""),
            tls_version=tls_version,
        )
        service_scores.append({"port": port, **result})
        all_cves.update(result["associated_cves"])
        all_threats.update(result["linddun_threats"])

    # Host score = max service score
    max_score = max(s["risk_score"] for s in service_scores)
    if max_score >= 9.0:
        severity = "critical"
    elif max_score >= 7.0:
        severity = "high"
    elif max_score >= 4.0:
        severity = "medium"
    else:
        severity = "low"

    return {
        "risk_score": max_score,
        "severity": severity,
        "all_cves": list(all_cves),
        "all_threats": list(all_threats),
        "service_scores": service_scores,
    }
