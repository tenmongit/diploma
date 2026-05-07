# Project State: SmartCity OSINT Platform

## Technical Stack
- **Backend Framework**: FastAPI (Python)
- **Task Queue**: Celery
- **Database**: PostgreSQL
- **Frontend**: React
- **Containerization**: Docker / Docker Compose

## Critical Business Rules
- **SCOPE**: Target smart cities in Kazakhstan (Almaty, Astana, Shymkent, etc.).
- **LEGAL STRICT RULE**: ONLY PASSIVE OSINT is allowed. ZERO active scanning, no Nmap, no direct TCP/UDP probes. Use only third-party APIs (Shodan, Censys, crt.sh).
- **SECURITY**: Zero hardcoded API keys. Always use `.env`.
- **RESILIENCE**: All third-party API interactions via Celery must implement pagination, handle `429 Too Many Requests`, and use exponential backoff.
