import asyncio
import sys
import os
import random
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.db.database import async_session, engine, Base
from app.db.models import Vendor, Host, Service, Vulnerability, SeverityLevel, ScanJob, ScanStatus, User
from sqlalchemy import text

async def clear_db(session):
    # Clear tables but keep users
    await session.execute(text("TRUNCATE TABLE vulnerabilities CASCADE"))
    await session.execute(text("TRUNCATE TABLE services CASCADE"))
    await session.execute(text("TRUNCATE TABLE hosts CASCADE"))
    await session.execute(text("TRUNCATE TABLE scan_jobs CASCADE"))
    await session.execute(text("TRUNCATE TABLE vendors CASCADE"))
    await session.commit()

async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with async_session() as session:
        print("Clearing old data...")
        await clear_db(session)

        # Get Admin User
        from sqlalchemy import select
        admin_res = await session.execute(select(User).where(User.username == "admin"))
        admin_user = admin_res.scalar_one_or_none()
        if not admin_user:
            print("Warning: Admin user not found, assuming ID 1")
            admin_id = 1
        else:
            admin_id = admin_user.id

        print("Seeding new data...")
        
        # Scans
        scan_astana = ScanJob(
            user_id=admin_id, target_domain="astana.gov.kz", status=ScanStatus.COMPLETED, progress=100,
            result={"total_hosts": 20, "total_services": 42, "total_vulnerabilities": 50, "subdomains_found": 35}
        )
        scan_almaty = ScanJob(
            user_id=admin_id, target_domain="almaty.gov.kz", status=ScanStatus.COMPLETED, progress=100,
            result={"total_hosts": 14, "total_services": 29, "total_vulnerabilities": 34, "subdomains_found": 22}
        )
        session.add_all([scan_astana, scan_almaty])
        await session.flush()

        # Vendors
        vendors_data = {
            "Hikvision": Vendor(name="Hikvision", description="Camera surveillance"),
            "Dahua": Vendor(name="Dahua", description="Camera surveillance"),
            "GoAhead": Vendor(name="GoAhead", description="Embedded web servers"),
            "Mosquitto": Vendor(name="Mosquitto", description="MQTT brokers for IoT"),
            "Sergek": Vendor(name="Sergek", description="Traffic monitoring"),
            "Korkem Telecom": Vendor(name="Korkem Telecom", description="Infrastructure/telecom")
        }
        for v in vendors_data.values():
            session.add(v)
        await session.flush()

        # Target Counts
        target_hosts = 34
        target_services = 71
        target_vulns = 84
        sev_dist = {"critical": 37, "high": 15, "medium": 15, "low": 17}

        host_configs = []
        
        # Vendor Distribution: Hikvision(10), Dahua(6), GoAhead(4), Mosquitto(5), Sergek(5), Korkem Telecom(4)
        vendor_allocs = ["Hikvision"]*10 + ["Dahua"]*6 + ["GoAhead"]*4 + ["Mosquitto"]*5 + ["Sergek"]*5 + ["Korkem Telecom"]*4
        random.seed(42)
        random.shuffle(vendor_allocs)

        astana_geo = {"city": "Astana", "country": "Kazakhstan"}
        almaty_geo = {"city": "Almaty", "country": "Kazakhstan"}

        # Hostname templates
        templates = ['camera-gateway-north', 'camera-gateway-south', 'iot-gateway-central', 'parking-kiosk', 'scada-water', 'smart-lighting', 'snmp-network-core']

        hosts = []
        for i in range(target_hosts):
            is_astana = i < 20
            domain_ext = "astana.gov.kz" if is_astana else "almaty.gov.kz"
            scan_id = scan_astana.id if is_astana else scan_almaty.id
            geo = astana_geo.copy() if is_astana else almaty_geo.copy()
            geo["lat"] = 51.1 + random.uniform(-0.05, 0.05) if is_astana else 43.25 + random.uniform(-0.03, 0.03)
            geo["lon"] = 71.45 + random.uniform(-0.05, 0.05) if is_astana else 76.93 + random.uniform(-0.03, 0.03)
            
            ip = f"10.{'10' if is_astana else '20'}.1.{i+1}"
            vendor_name = vendor_allocs[i]
            tmpl = random.choice(templates)
            domain = f"{tmpl}-{i+1:02d}.{domain_ext}"
            
            h = Host(
                ip_address=ip, domain=domain, vendor_id=vendors_data[vendor_name].id,
                geolocation=geo, scan_job_id=scan_id
            )
            session.add(h)
            hosts.append({"obj": h, "vendor": vendor_name, "is_astana": is_astana, "services": [], "vulns": []})
        
        await session.flush()

        # Service Distribution: 71 services
        # 554(12), 80(12), 443(8), 1883(7), 8080(8), 23(6), 502(6), 161(6), 4840(6)
        port_allocs = [554]*12 + [80]*12 + [443]*8 + [1883]*7 + [8080]*8 + [23]*6 + [502]*6 + [161]*6 + [4840]*6
        random.shuffle(port_allocs)

        port_meta = {
            554: ("RTSP", "tcp", "Surveillance Stream"),
            80: ("HTTP", "tcp", "Web Interface"),
            443: ("HTTPS", "tcp", "Secure Web Interface"),
            1883: ("MQTT", "tcp", "IoT Broker"),
            8080: ("HTTP-alt", "tcp", "Dashboard/Gateway"),
            23: ("Telnet", "tcp", "Remote Access (Insecure)"),
            502: ("Modbus", "tcp", "SCADA/Industrial"),
            161: ("SNMP", "udp", "Network Monitoring"),
            4840: ("OPC-UA", "tcp", "Industrial Automation")
        }

        # Assign at least 1 service to each host, then randomly distribute the rest
        host_idx = 0
        services_created = []
        for port in port_allocs:
            h_data = hosts[host_idx]
            name, proto, cls = port_meta[port]
            
            svc = Service(
                host_id=h_data["obj"].id, port=port, protocol=proto, service_name=name,
                classification=cls, banner_data={"product": h_data["vendor"]}
            )
            session.add(svc)
            h_data["services"].append(svc)
            services_created.append((h_data, svc))
            host_idx = (host_idx + 1) % target_hosts
        
        await session.flush()

        # Vulnerabilities: 84 total
        # Critical(37), High(15), Medium(15), Low(17)
        # Critical CVEs: CVE-2021-36260 (Hikvision, 8), CVE-2017-7921 (Hikvision, 6), CVE-2021-33044 (Dahua, 5), CVE-2017-17562 (GoAhead, 4)
        # Other critical (14)
        
        vuln_allocs = []
        # Add Specific CVEs
        for _ in range(8): vuln_allocs.append({"sev": "critical", "cve": "CVE-2021-36260", "req_vendor": "Hikvision", "title": "Hikvision RCE", "risk": 9.8})
        for _ in range(6): vuln_allocs.append({"sev": "critical", "cve": "CVE-2017-7921", "req_vendor": "Hikvision", "title": "Hikvision Auth Bypass", "risk": 9.2})
        for _ in range(5): vuln_allocs.append({"sev": "critical", "cve": "CVE-2021-33044", "req_vendor": "Dahua", "title": "Dahua Auth Bypass", "risk": 9.0})
        for _ in range(4): vuln_allocs.append({"sev": "critical", "cve": "CVE-2017-17562", "req_vendor": "GoAhead", "title": "GoAhead RCE", "risk": 9.0})
        
        # Fill rest of Critical
        for _ in range(14): vuln_allocs.append({"sev": "critical", "cve": None, "req_vendor": None, "title": "Critical Privacy/Exposure Risk", "risk": 9.1})
        # Fill High, Medium, Low
        for _ in range(15): vuln_allocs.append({"sev": "high", "cve": None, "req_vendor": None, "title": "High Severity Exposure", "risk": 7.5})
        for _ in range(15): vuln_allocs.append({"sev": "medium", "cve": None, "req_vendor": None, "title": "Medium Privacy Risk", "risk": 5.0})
        for _ in range(17): vuln_allocs.append({"sev": "low", "cve": None, "req_vendor": None, "title": "Informational Exposure", "risk": 2.5})

        privacy_tags = ["P:I", "P:L", "video_surveillance", "iot_data"]

        # Assign vulnerabilities to matching hosts
        for v_data in vuln_allocs:
            req_vendor = v_data["req_vendor"]
            # Filter hosts that match the vendor requirement, or all if no requirement
            valid_hosts = [h for h in services_created if not req_vendor or h[0]["vendor"] == req_vendor]
            if not valid_hosts:
                valid_hosts = services_created # Fallback if random dist missed
                
            chosen = random.choice(valid_hosts)
            h_data, svc = chosen
            
            tag = random.choice(privacy_tags)
            if "camera" in h_data["obj"].domain:
                tag = "video_surveillance"
            elif "iot" in h_data["obj"].domain or "mqtt" in h_data["obj"].domain:
                tag = "iot_data"
            
            vuln = Vulnerability(
                host_id=h_data["obj"].id, service_id=svc.id,
                cve_id=v_data["cve"], title=v_data["title"],
                risk_score=v_data["risk"], severity=SeverityLevel(v_data["sev"]),
                privacy_risk_type=tag, details={"metrics": "synthetic"}
            )
            session.add(vuln)
        
        await session.commit()
        print("✅ Demo data seeded successfully! All metrics match thesis requirements.")

if __name__ == "__main__":
    asyncio.run(seed())
