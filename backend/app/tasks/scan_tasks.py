"""
Celery scan orchestration pipeline — multi-city OSINT collection.

Architecture:
─────────────────────────────────────────────────────────────────────────────
  run_full_scan(scan_id, target_domain)
      │
      ├─► [Phase 1] DNS enumeration of target_domain (async, via asyncio)
      ├─► [Phase 2] crt.sh subdomain discovery (async, via asyncio)
      │
      ├─► [Phase 3] FOR EACH city IN SCAN_CITIES_KZ:
      │       ├─► scan_city_shodan(city, scan_id)   ← subtask with retry/backoff
      │       └─► scan_city_censys(city, scan_id)   ← subtask with retry/backoff
      │
      ├─► [Phase 4] Merge all results by IP, classify + score each host
      └─► [Phase 5] Persist to PostgreSQL, update ScanJob to COMPLETED

Key design decisions:
  - Subtasks (scan_city_shodan / scan_city_censys) use autoretry_for + retry_backoff
    so each city retries independently on API errors without failing the whole scan.
  - Collectors raise ValueError if API keys are missing — the orchestrator catches
    this and skips the collector gracefully (allows running with only one key).
  - All OSINT collectors use sync methods (Shodan SDK is sync; async wrappers
    add overhead with no benefit in a Celery worker context).
  - Progress is updated atomically at each phase boundary.
─────────────────────────────────────────────────────────────────────────────
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import shodan.exception
from celery import shared_task
from celery.exceptions import SoftTimeLimitExceeded
from censys.common.exceptions import CensysUnauthorizedException, CensysException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.tasks.celery_app import celery_app
from app.core.config import get_settings
from app.db.models import (
    ScanJob, Host, Service, Vulnerability, Vendor,
    ScanStatus, SeverityLevel,
)
from app.osint.dns_enum import DnsEnumerator
from app.osint.crtsh_collector import CrtshCollector
from app.osint.shodan_collector import ShodanCollector
from app.osint.censys_collector import CensysCollector
from app.osint.demo_collector import DemoCollector
from app.engine.classifier import classify_host_services
from app.engine.risk_scorer import score_host

logger = logging.getLogger(__name__)
settings = get_settings()

# ─── Synchronous DB Setup ────────────────────────────────────────────────────
# Celery workers are synchronous (no asyncio event loop).
# We use a plain psycopg2 engine for DB operations in tasks.
SYNC_DB_URL = settings.DATABASE_URL.replace("+asyncpg", "+psycopg2")
sync_engine = create_engine(SYNC_DB_URL, pool_size=5, max_overflow=5, pool_pre_ping=True)
SyncSession = sessionmaker(bind=sync_engine)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run_async(coro) -> Any:
    """Run an async coroutine synchronously inside a Celery worker."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _update_progress(
    db: Session,
    scan_id: int,
    progress: int,
    status: ScanStatus = ScanStatus.RUNNING,
) -> None:
    """Atomically update scan job progress and status."""
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if scan:
        scan.progress = min(progress, 100)  # Cap at 100
        scan.status = status
        scan.updated_at = datetime.now(timezone.utc)
        db.commit()


def _get_or_create_vendor(db: Session, product_name: str) -> int | None:
    """
    Look up a vendor by product name prefix, creating one if not found.

    Uses a case-insensitive prefix match (first word of product name)
    to group products like "Hikvision DS-2CD" under vendor "Hikvision".
    """
    if not product_name:
        return None
    # Use only the first word as the vendor identifier.
    vendor_name = product_name.strip().split()[0] if product_name.strip() else ""
    if not vendor_name:
        return None

    vendor = db.query(Vendor).filter(Vendor.name.ilike(f"%{vendor_name}%")).first()
    if not vendor:
        vendor = Vendor(name=vendor_name)
        db.add(vendor)
        db.flush()
    return vendor.id


def _persist_host_results(
    db: Session,
    hosts_map: dict[str, dict],
    scan_id: int,
) -> tuple[int, int, int, dict]:
    """
    Classify, score, and persist all collected hosts to the database.

    Args:
        db: Synchronous SQLAlchemy session.
        hosts_map: Dict mapping IP → merged host data from all collectors.
        scan_id: ScanJob ID to associate hosts with.

    Returns:
        Tuple of (total_hosts, total_services, total_vulns, severity_counts).
    """
    total_hosts = 0
    total_services = 0
    total_vulns = 0
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for host_key, host_data in hosts_map.items():
        ip = host_data.get("ip_address", host_key)
        if not ip:
            hostnames_for_key = list(host_data.get("hostnames", []))
            ip = hostnames_for_key[0] if hostnames_for_key else host_key
        # ── Deduplicate services by port ──────────────────────────────────
        # Multiple dork queries can return the same port for the same host.
        # Deduplicate by (port, protocol) before classification.
        seen_ports: set[tuple] = set()
        unique_services = []
        for svc in host_data.get("services", []):
            key = (svc.get("port"), svc.get("protocol", "tcp"))
            if key not in seen_ports and svc.get("port"):
                seen_ports.add(key)
                unique_services.append(svc)
        host_data["services"] = unique_services

        # ── Classify and score ────────────────────────────────────────────
        classified_services = classify_host_services(host_data["services"])
        host_score = score_host(classified_services)

        # ── Detect primary domain and vendor ─────────────────────────────
        hostnames = list(set(host_data.get("hostnames", [])))
        domain = next((h for h in hostnames if h), None)

        vendor_id = None
        for svc in classified_services:
            bd = svc.get("banner_data", {})
            product = bd.get("product", "") if isinstance(bd, dict) else ""
            vid = _get_or_create_vendor(db, product)
            if vid:
                vendor_id = vid
                break

        # ── Persist Host ──────────────────────────────────────────────────
        host = Host(
            ip_address=ip,
            domain=domain,
            vendor_id=vendor_id,
            geolocation=host_data.get("geolocation", {}),
            scan_job_id=scan_id,
        )
        db.add(host)
        db.flush()
        total_hosts += 1

        # ── Persist Services and Vulnerabilities ──────────────────────────
        for svc in classified_services:
            bd = svc.get("banner_data", {})
            service = Service(
                host_id=host.id,
                port=svc.get("port", 0),
                protocol=svc.get("protocol", "tcp"),
                service_name=svc.get("service_name", ""),
                banner_data=bd if isinstance(bd, dict) else {},
                classification=svc.get("classification", ""),
            )
            db.add(service)
            db.flush()
            total_services += 1

            # Match the risk score for this specific port.
            matching_scores = [
                s for s in host_score.get("service_scores", [])
                if s["port"] == svc.get("port")
            ]
            if not matching_scores or matching_scores[0]["risk_score"] <= 0:
                continue

            ss = matching_scores[0]
            sev = SeverityLevel(ss["severity"])
            severity_counts[ss["severity"]] = severity_counts.get(ss["severity"], 0) + 1

            cves: list[str] = ss.get("associated_cves", [])
            linddun_tags = ", ".join(ss.get("linddun_threats", []))
            score_details = {
                "breakdown": ss["breakdown"],
                "privacy_metrics": ss["privacy_metrics"],
            }

            if cves:
                # One Vulnerability row per CVE for proper tracking.
                for cve in cves:
                    vuln = Vulnerability(
                        host_id=host.id,
                        service_id=service.id,
                        cve_id=cve,
                        privacy_risk_type=linddun_tags,
                        risk_score=ss["risk_score"],
                        severity=sev,
                        title=f"{cve} — {svc.get('classification', '')}",
                        details=score_details,
                    )
                    db.add(vuln)
                    total_vulns += 1
            else:
                # Privacy risk without a specific CVE.
                vuln = Vulnerability(
                    host_id=host.id,
                    service_id=service.id,
                    cve_id=None,
                    privacy_risk_type=linddun_tags,
                    risk_score=ss["risk_score"],
                    severity=sev,
                    title=f"Privacy Risk — {svc.get('classification', '')}",
                    details=score_details,
                )
                db.add(vuln)
                total_vulns += 1

    db.commit()
    return total_hosts, total_services, total_vulns, severity_counts


def _merge_results(
    host_map: dict[str, dict],
    new_results: list[dict],
) -> None:
    """
    Merge a new list of host results into an existing IP-keyed map.

    Extends services and hostnames for existing IPs; inserts new ones.
    """
    for result in new_results:
        ip = result.get("ip_address", "")
        hostnames = list(result.get("hostnames", []))
        if not ip and not hostnames:
            continue
        key = ip or f"hostname:{hostnames[0]}"
        if key not in host_map:
            host_map[key] = {
                "ip_address": ip,
                "hostnames": hostnames,
                "geolocation": result.get("geolocation", {}),
                "services": list(result.get("services", [])),
            }
        else:
            existing = host_map[key]
            existing["services"].extend(result.get("services", []))
            existing_h = set(existing["hostnames"])
            existing_h.update(hostnames)
            existing["hostnames"] = list(existing_h)
            if not existing["geolocation"] and result.get("geolocation"):
                existing["geolocation"] = result["geolocation"]



# ─── Main Orchestrator Task ───────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="app.tasks.scan_tasks.run_full_scan",
    max_retries=1,
    default_retry_delay=60,
)
def run_full_scan(self, scan_id: int, target_domain: str, scan_mode: str = "real") -> dict:
    """
    Main orchestrator: runs the full multi-city OSINT pipeline.

    Pipeline:
        Phase 1 (0→10%):   DNS enumeration of target_domain
        Phase 2 (10→20%):  crt.sh Certificate Transparency subdomain discovery
        Phase 3 (20→80%):  Multi-city Shodan + Censys scanning
                            Progress increments per-city: 60% / num_cities
        Phase 4 (80→95%):  Classification + risk scoring + DB persistence
        Phase 5 (95→100%): Finalize ScanJob record

    Args:
        scan_id: ID of the ScanJob record in PostgreSQL.
        target_domain: Apex domain (e.g., "gov.kz") — used for DNS + crt.sh.
                       City-based scanning uses SCAN_CITIES_KZ, not this domain.
    """
    db = SyncSession()
    # Master host map: IP → merged host data from ALL cities and ALL collectors.
    hosts_map: dict[str, dict] = {}
    subdomains: list[str] = []

    try:
        scan_mode = scan_mode if scan_mode in ("real", "demo") else "real"
        logger.info(f"[Scan {scan_id}] Starting full scan. Domain: '{target_domain}'. Mode: '{scan_mode}'")
        _update_progress(db, scan_id, 2, ScanStatus.RUNNING)

        cities = settings.cities_list
        logger.info(f"[Scan {scan_id}] Target cities: {cities}")

        if scan_mode == "demo":
            logger.info(f"[Scan {scan_id}] Demo mode enabled: using synthetic defense dataset")
            _update_progress(db, scan_id, 15)
            demo_results = DemoCollector().collect(target_domain)
            _merge_results(hosts_map, demo_results)
            subdomains = [
                h for r in demo_results for h in r.get("hostnames", [])
            ]
            _update_progress(db, scan_id, 80)
            logger.info(f"[Scan {scan_id}] Demo dataset loaded: {len(demo_results)} hosts")
        else:

            # ── Phase 1: DNS Enumeration (2→10%) ─────────────────────────────
            logger.info(f"[Scan {scan_id}] Phase 1: DNS Enumeration")
            try:
                dns_enum = DnsEnumerator()
                dns_results = _run_async(dns_enum.collect(target_domain))
                _merge_results(hosts_map, dns_results)
                logger.info(f"[Scan {scan_id}] DNS found {len(dns_results)} records")
            except Exception as exc:
                logger.warning(f"[Scan {scan_id}] DNS enumeration failed (non-fatal): {exc}")
            _update_progress(db, scan_id, 10)

            # ── Phase 2: crt.sh Subdomain Discovery (10→20%) ─────────────────
            logger.info(f"[Scan {scan_id}] Phase 2: Certificate Transparency (crt.sh)")
            try:
                crtsh = CrtshCollector()
                crtsh_results = _run_async(crtsh.collect(target_domain))
                _merge_results(hosts_map, crtsh_results)
                subdomains = [
                    h for r in crtsh_results for h in r.get("hostnames", [])
                ]
                logger.info(f"[Scan {scan_id}] crt.sh found {len(subdomains)} subdomains")
                if subdomains:
                    dns_subdomain_results = _run_async(DnsEnumerator().collect(target_domain, subdomains=subdomains))
                    _merge_results(hosts_map, dns_subdomain_results)
                    logger.info(
                        f"[Scan {scan_id}] DNS resolved {len(dns_subdomain_results)} "
                        "records from crt.sh subdomains"
                    )
            except Exception as exc:
                logger.warning(f"[Scan {scan_id}] crt.sh failed (non-fatal): {exc}")
            _update_progress(db, scan_id, 20)

            # ── Phase 3: Domain-based Shodan + Censys (20→80%) ────────────────
            logger.info(f"[Scan {scan_id}] Phase 3: Domain-based OSINT scanning (free tier)")
            _update_progress(db, scan_id, 30)

            # Initialize collectors once outside the loop to reuse sessions/auth.
            shodan_collector = None
            try:
                shodan_collector = ShodanCollector()
            except Exception as exc:
                logger.warning(f"[Scan {scan_id}] Shodan collector init failed: {exc}")

            # Censys disabled - free tier only supports Platform UI, not API access
            logger.info(f"[Scan {scan_id}] Censys collector disabled - free tier does not support API access")

            # ── Shodan (domain-based, free tier compatible) ───────────────────
            if shodan_collector:
                try:
                    logger.info(f"[Shodan][scan={scan_id}] Starting domain lookup: '{target_domain}'")
                    shodan_results = _run_async(shodan_collector.collect(target_domain))
                    _merge_results(hosts_map, shodan_results)
                    logger.info(f"[Scan {scan_id}] Shodan '{target_domain}': {len(shodan_results)} hosts merged")
                except Exception as exc:
                    logger.warning(f"[Scan {scan_id}] Shodan failed for '{target_domain}': {exc}")

            _update_progress(db, scan_id, 80)
            logger.info(f"[Scan {scan_id}] Phase 3 complete: {len(hosts_map)} unique hosts from domain-based queries")

        # ── Phase 4: Classify, Score, Persist (80→95%) ───────────────────
        logger.info(f"[Scan {scan_id}] Phase 4: Classification + Scoring + DB Persistence")
        total_hosts, total_services, total_vulns, severity_counts = _persist_host_results(
            db, hosts_map, scan_id
        )
        logger.info(
            f"[Scan {scan_id}] Persisted: {total_hosts} hosts, "
            f"{total_services} services, {total_vulns} vulnerabilities"
        )
        _update_progress(db, scan_id, 95)

        # ── Phase 5: Finalize (95→100%) ───────────────────────────────────
        logger.info(f"[Scan {scan_id}] Phase 5: Finalizing")
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.COMPLETED
            scan.progress = 100
            scan.result = {
                "total_hosts": total_hosts,
                "total_services": total_services,
                "total_vulnerabilities": total_vulns,
                "severity_counts": severity_counts,
                "subdomains_found": len(subdomains),
                "cities_scanned": cities,
                "scan_mode": scan_mode,
                "data_notice": "Synthetic demo dataset for academic defense" if scan_mode == "demo" else "Real passive OSINT collection",
            }
            scan.updated_at = datetime.now(timezone.utc)
        db.commit()

        logger.info(
            f"[Scan {scan_id}] ✅ Complete — "
            f"{total_hosts} hosts | {total_services} services | {total_vulns} vulns"
        )
        return {
            "scan_id": scan_id,
            "status": "completed",
            "total_hosts": total_hosts,
            "total_services": total_services,
            "total_vulnerabilities": total_vulns,
            "cities_scanned": cities,
            "scan_mode": scan_mode,
        }

    except SoftTimeLimitExceeded:
        # The worker received a soft time limit signal — gracefully save
        # whatever partial results were already persisted.
        logger.warning(
            f"[Scan {scan_id}] Soft time limit exceeded. "
            f"Saving partial results ({len(hosts_map)} hosts in memory)."
        )
        try:
            partial_hosts, partial_services, partial_vulns, partial_severity = \
                _persist_host_results(db, hosts_map, scan_id)
        except Exception:
            partial_hosts = partial_services = partial_vulns = 0
            partial_severity = {}

        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Scan timed out — partial results saved."
            scan.progress = 95
            scan.result = {
                "total_hosts": partial_hosts,
                "total_services": partial_services,
                "total_vulnerabilities": partial_vulns,
                "severity_counts": partial_severity,
                "partial": True,
            }
            scan.updated_at = datetime.now(timezone.utc)
            db.commit()

    except Exception as exc:
        logger.error(f"[Scan {scan_id}] ❌ Failed: {exc}", exc_info=True)
        db.rollback()
        scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = str(exc)[:2000]
            scan.updated_at = datetime.now(timezone.utc)
            db.commit()
        raise

    finally:
        db.close()
