"""Seed database with demo data for development."""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.db.database import async_session, engine, Base
from app.db.models import Vendor, Host, Service, Vulnerability, SeverityLevel
from app.core.security import hash_password


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        # Vendors
        vendors = [
            Vendor(name="Hikvision", bin_code="HKV-001", description="Chinese surveillance camera manufacturer"),
            Vendor(name="Dahua", bin_code="DH-002", description="Video surveillance technology company"),
            Vendor(name="Sergek", bin_code="SRG-003", description="Kazakhstan Smart City traffic monitoring"),
            Vendor(name="Schneider Electric", bin_code="SE-004", description="Industrial automation and IoT"),
            Vendor(name="Mosquitto", bin_code="MQ-005", description="Eclipse MQTT broker for IoT"),
        ]
        for v in vendors:
            session.add(v)
        await session.flush()

        vendor_map = {v.name: v.id for v in vendors}

        # Hosts with geolocation
        hosts_data = [
            {
                "ip": "185.125.46.34", "domain": "cam-01.astana.gov.kz",
                "vendor": "Hikvision",
                "geo": {"lat": 51.1605, "lon": 71.4704, "city": "Astana", "country": "Kazakhstan"},
                "services": [
                    {"port": 554, "proto": "tcp", "name": "RTSP", "classification": "Surveillance Node",
                     "banner": {"banner": "RTSP/1.0 200 OK\r\nServer: Hikvision-Webs", "product": "Hikvision", "version": "5.4.5"}},
                    {"port": 80, "proto": "tcp", "name": "HTTP", "classification": "Camera Web UI",
                     "banner": {"banner": "HTTP/1.1 200 OK\r\nServer: DNVRS-Webs", "product": "Hikvision Web UI"}},
                ],
                "vulns": [
                    {"cve": "CVE-2021-36260", "title": "CVE-2021-36260 — Surveillance Node", "risk": 8.5, "sev": "high",
                     "privacy": "Identifiability, Linkability",
                     "details": {"breakdown": {"port_exposure": 2.5, "privacy_impact": 4.0}, "privacy_metrics": {"P:L": 3.5, "P:I": 4.0}}},
                    {"cve": "CVE-2017-7921", "title": "CVE-2017-7921 — Hikvision Auth Bypass", "risk": 9.2, "sev": "critical",
                     "privacy": "Identifiability",
                     "details": {"breakdown": {"port_exposure": 2.5, "software_risk": 3.0, "privacy_impact": 3.7}, "privacy_metrics": {"P:I": 4.0}}},
                ],
            },
            {
                "ip": "185.125.46.71", "domain": "sensor-hub.astana.gov.kz",
                "vendor": "Sergek",
                "geo": {"lat": 51.1280, "lon": 71.4306, "city": "Astana", "country": "Kazakhstan"},
                "services": [
                    {"port": 8080, "proto": "tcp", "name": "HTTP-Proxy", "classification": "IoT Gateway",
                     "banner": {"banner": "HTTP/1.1 200 OK\r\nServer: IoT-Gateway/2.1", "product": "IoT Gateway", "version": "2.1"}},
                    {"port": 80, "proto": "tcp", "name": "HTTP", "classification": "Sergek Dashboard",
                     "banner": {"banner": "HTTP/1.1 302 Found\r\nLocation: /login", "product": "Sergek Dashboard", "version": "3.2"}},
                ],
                "vulns": [
                    {"cve": None, "title": "Privacy Risk — Sergek Dashboard", "risk": 5.5, "sev": "medium",
                     "privacy": "Linkability",
                     "details": {"breakdown": {"port_exposure": 1.0, "privacy_impact": 3.0}, "privacy_metrics": {"P:L": 3.0}}},
                ],
            },
            {
                "ip": "91.204.239.10", "domain": "mqtt.astana.gov.kz",
                "vendor": "Mosquitto",
                "geo": {"lat": 51.0906, "lon": 71.4183, "city": "Astana", "country": "Kazakhstan"},
                "services": [
                    {"port": 1883, "proto": "tcp", "name": "MQTT", "classification": "IoT MQTT Broker",
                     "banner": {"banner": "MQTT/3.1.1", "product": "Mosquitto", "version": "2.0.15"}},
                ],
                "vulns": [
                    {"cve": None, "title": "Privacy Risk — IoT MQTT Broker", "risk": 4.5, "sev": "medium",
                     "privacy": "Linkability",
                     "details": {"breakdown": {"port_exposure": 2.0, "protocol_security": 1.5}, "privacy_metrics": {"P:L": 2.0}}},
                ],
            },
            {
                "ip": "185.125.46.90", "domain": "cam-legacy.astana.gov.kz",
                "vendor": "Dahua",
                "geo": {"lat": 51.1450, "lon": 71.4890, "city": "Astana", "country": "Kazakhstan"},
                "services": [
                    {"port": 23, "proto": "tcp", "name": "Telnet", "classification": "Telnet Service (Insecure)",
                     "banner": {"banner": "Dahua DVR login:", "product": "Dahua"}},
                    {"port": 554, "proto": "tcp", "name": "RTSP", "classification": "Surveillance Node",
                     "banner": {"banner": "RTSP/1.0 200 OK\r\nServer: Dahua-RTSP", "product": "Dahua", "version": "4.3.0"}},
                ],
                "vulns": [
                    {"cve": "CVE-2021-33044", "title": "CVE-2021-33044 — Surveillance Node", "risk": 8.0, "sev": "high",
                     "privacy": "Identifiability, Linkability",
                     "details": {"breakdown": {"port_exposure": 3.0, "software_risk": 2.5, "privacy_impact": 4.5}, "privacy_metrics": {"P:L": 3.5, "P:I": 4.0}}},
                ],
            },
            {
                "ip": "185.125.47.15", "domain": "scada-gw.astana.gov.kz",
                "vendor": "Schneider Electric",
                "geo": {"lat": 51.1700, "lon": 71.4500, "city": "Astana", "country": "Kazakhstan"},
                "services": [
                    {"port": 502, "proto": "tcp", "name": "Modbus", "classification": "SCADA/Modbus Endpoint",
                     "banner": {"banner": "", "product": "Schneider Electric Modicon", "version": "M340"}},
                    {"port": 80, "proto": "tcp", "name": "HTTP", "classification": "Embedded Web Server",
                     "banner": {"banner": "HTTP/1.1 200\r\nServer: GoAhead-Webs", "product": "GoAhead", "version": "3.6.5"}},
                ],
                "vulns": [
                    {"cve": "CVE-2017-17562", "title": "CVE-2017-17562 — GoAhead RCE", "risk": 9.0, "sev": "critical",
                     "privacy": "Non-Repudiation",
                     "details": {"breakdown": {"port_exposure": 3.0, "software_risk": 2.0, "privacy_impact": 3.0}, "privacy_metrics": {"P:NR": 3.0}}},
                ],
            },
        ]

        for hd in hosts_data:
            host = Host(
                ip_address=hd["ip"],
                domain=hd["domain"],
                vendor_id=vendor_map.get(hd["vendor"]),
                geolocation=hd["geo"],
            )
            session.add(host)
            await session.flush()

            for sd in hd["services"]:
                svc = Service(
                    host_id=host.id,
                    port=sd["port"],
                    protocol=sd["proto"],
                    service_name=sd["name"],
                    banner_data=sd["banner"],
                    classification=sd["classification"],
                )
                session.add(svc)
                await session.flush()

            for vd in hd["vulns"]:
                vuln = Vulnerability(
                    host_id=host.id,
                    cve_id=vd["cve"],
                    title=vd["title"],
                    risk_score=vd["risk"],
                    severity=SeverityLevel(vd["sev"]),
                    privacy_risk_type=vd["privacy"],
                    details=vd["details"],
                )
                session.add(vuln)

        await session.commit()
        print("✅ Demo data seeded successfully!")


if __name__ == "__main__":
    asyncio.run(seed())
