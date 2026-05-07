# SmartCity OSINT Platform

A scalable, distributed web application for automated discovery, classification, and mapping of privacy threats in Smart City infrastructure.

## Architecture

- **Backend**: Python 3.11 + FastAPI (async API)
- **Frontend**: React 18 + Vite + Leaflet.js
- **Database**: PostgreSQL 15 (with JSONB)
- **Task Queue**: Celery + Redis
- **Containerization**: Docker Compose

## Quick Start

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Start all services
docker compose up -d --build

# 3. Access the application
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
# Default login: admin / admin123
```

## Project Structure

```
diploma/
├── docker-compose.yml
├── .env.example
├── Makefile
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/           # Database migrations
│   └── app/
│       ├── main.py         # FastAPI app factory
│       ├── core/           # Config, security
│       ├── db/             # Models, database
│       ├── api/            # REST API routes
│       ├── schemas/        # Pydantic models
│       ├── osint/          # OSINT collectors
│       ├── engine/         # Classification & scoring
│       └── tasks/          # Celery tasks
└── frontend/
    ├── Dockerfile
    ├── package.json
    └── src/
        ├── App.jsx         # Root component + routing
        ├── index.css       # Design system
        ├── api/            # Axios client
        ├── context/        # Auth context
        ├── components/     # Layout, shared components
        └── pages/          # Dashboard, Map, Scan, Hosts, Reports
```

## Makefile Commands

```bash
make up        # Start all services
make down      # Stop all services
make logs      # Follow all logs
make logs-api  # Follow API logs only
make migrate   # Run DB migrations
make restart   # Restart API + Worker
make clean     # Remove everything including volumes
```

## OSINT Modules

| Module | Source | API Key Required |
|--------|--------|-----------------|
| Shodan | `app/osint/shodan_collector.py` | Yes (optional for demo) |
| Censys | `app/osint/censys_collector.py` | Yes (optional for demo) |
| crt.sh | `app/osint/crtsh_collector.py` | No (public API) |
| DNS    | `app/osint/dns_enum.py`        | No |

## API Documentation

Once running, visit `http://localhost:8000/docs` for the interactive Swagger UI.
