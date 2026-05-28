# Experimental Results Claim Check

This report compares the proposed diploma text against the current SmartCity OSINT Platform codebase and the local PostgreSQL database snapshot.

## Evidence Sources

- `PROJECT_STATE.md`
- `backend/app/tasks/scan_tasks.py`
- `backend/app/osint/shodan_collector.py`
- `backend/app/osint/demo_collector.py`
- `backend/app/engine/classifier.py`
- `backend/app/engine/risk_scorer.py`
- Local PostgreSQL database queried through Docker Compose

## Current Database Snapshot

| Metric | Actual Value |
|---|---:|
| Scan jobs | 19 |
| Completed scans | 19 |
| Host rows | 50 |
| Unique IP addresses | 34 |
| Service rows | 71 |
| Vulnerability rows | 84 |
| Vendors | 15 |
| Average completed scan duration | 58 seconds |

## Severity Distribution

| Severity | Vulnerability Rows | Percentage |
|---|---:|---:|
| Critical | 37 | 44.0% |
| High | 15 | 17.9% |
| Medium | 15 | 17.9% |
| Low | 17 | 20.2% |

## Latest Controlled Scenario Scan

| Field | Value |
|---|---:|
| Scan ID | 19 |
| Target domain | `almaty.gov.kz` |
| Hosts | 18 |
| Services | 26 |
| Vulnerability rows | 32 |
| Unique IP addresses | 18 |
| Critical findings | 18 |
| High findings | 6 |
| Medium findings | 5 |
| Low findings | 3 |

## Draft Claim Evaluation

| Draft Claim | Match Status | Actual Evidence / Recommended Correction |
|---|---|---|
| Conventional third-party active penetration testing was not used | Matches | Project rules and code enforce passive OSINT only. |
| Validation used internal self-assessment | Matches | Controlled scenario and local database validation support this. |
| System compared against LINDDUN | Matches | `risk_scorer.py` maps privacy tags to Linkability, Identifiability, and Non-Repudiation. |
| System compared against MITRE ATT&CK for ICS | Partially supported | Code does not implement MITRE ATT&CK mappings. You can mention conceptual alignment with ICS exposure categories, but not direct ATT&CK technique mapping. |
| 100 classified service banners were checked | Does not match current DB | Current DB has only 71 service records total. Use: “the available classified service records in PostgreSQL were inspected,” or run more controlled scans before claiming 100. |
| Results compared against raw Shodan dataset | Partially supported | Real mode uses Shodan hostname queries; controlled scenario records are generated internally. Use “raw OSINT or scenario banner metadata.” |
| 1,245 unique publicly exposed IP addresses | Does not match | Current DB has 34 unique IP addresses and 50 host rows. |
| 3,420 exposed services | Does not match | Current DB has 71 services. |
| 87 critical, 412 high, 510 medium, 236 low services | Does not match | Current DB vulnerability rows: 37 critical, 15 high, 15 medium, 17 low. Latest controlled scan: 18 critical, 6 high, 5 medium, 3 low. |
| Critical findings were unencrypted surveillance feeds and unauthenticated databases | Partially supported | Surveillance/RTSP findings exist. No database-service evidence was found in the current classification distribution. Remove unauthenticated database claim unless implemented and evidenced. |
| Average full scan took 14 minutes | Does not match | Current DB average completed scan duration is 58 seconds. |
| Worker RAM usage below 512 MiB | Not evidenced | No RAM measurement logs were found in DB/code artifacts. Can state Docker worker is lightweight, but not a measured RAM claim unless collected. |
| Free-tier Shodan limitations affected depth | Matches | Current code uses domain-based `hostname:"<target_domain>"` query and disables Censys API in free-tier mode. |
| Findings are risk indicators, not verified intrusions | Matches | This aligns with passive-only project rules and risk-scoring design. |

## Main Corrections Needed

- Replace unsupported large-scale numbers with actual database metrics or clearly label them as hypothetical target-scale examples.
- Replace “attacked assets” with “analyzed assets,” “identified services,” or “risk findings.”
- Avoid saying exploitability, authentication state, or compromise was confirmed.
- Do not claim direct MITRE ATT&CK implementation unless a mapping table is added to the code or appendix.
- Do not claim 100 manually checked service banners unless additional records are generated and manually reviewed.

## Defensible Quantitative Statement

A defensible current statement is:

> In the current local experimental database, the platform contains 19 completed scan jobs, 50 persisted host rows representing 34 unique IP addresses, 71 classified services, and 84 vulnerability/risk records. The most recent controlled city-scale scenario produced 18 hosts, 26 services, and 32 risk records. The observed vulnerability-row severity distribution across the database was 37 critical, 15 high, 15 medium, and 17 low findings.

