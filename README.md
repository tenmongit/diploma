# SmartCity OSINT Platform

This repository contains the source code for the **SmartCity OSINT Platform**, a passive infrastructure and privacy threat mapping tool for Smart Cities.

## Project Description

The SmartCity OSINT Platform is an asynchronous, scalable system designed to automatically discover, classify, and evaluate exposed infrastructure in Smart City environments (e.g., Astana, Almaty). It utilizes passive OSINT sources to map connected devices (IoT gateways, surveillance cameras, SCADA systems) without actively probing or interfering with the operational technology.

### Architecture

The system is built on a modern, containerized technology stack:
- **Backend:** FastAPI (Python) for high-performance async API endpoints.
- **Frontend:** React + Vite for a responsive, dashboard-driven user interface.
- **Database:** PostgreSQL for robust relational data storage of assets and vulnerabilities.
- **Task Queue:** Celery + Redis for asynchronous processing of long-running OSINT scans.
- **Deployment:** Docker & Docker Compose for seamless cross-platform environments.

## Prerequisites

To run this platform locally, you must have the following installed on your system:
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Demonstration Mode (Quick Start)

The following instructions will start the platform in "Demonstration Mode", which seeds the database with synthetic data representing the exact findings presented in the project's Experimental Results (Chapter 3) and Appendices.

1. **Configure Environment:**
   Copy the example environment file. The default settings are safe for demonstration and require no API keys.
   ```bash
   cp .env.example .env
   ```

2. **Start Services:**
   Use Docker Compose to build and start all required containers in detached mode.
   ```bash
   docker compose up --build -d
   ```

3. **Seed Synthetic Data:**
   Run the data seeding script within the backend container. This populates the database with exact thesis metrics (34 hosts, 71 services, 84 vulnerabilities across Astana and Almaty).
   ```bash
   docker compose exec backend python seed_demo_data.py
   ```

## Accessing the Platform

Once the services are running and data is seeded, you can access the platform through your web browser:

- **Frontend Dashboard:** [http://localhost:3000](http://localhost:3000)
- **FastAPI Swagger UI (API Docs):** [http://localhost:8000/docs](http://localhost:8000/docs)

### Default Credentials
Log in to the Frontend Dashboard using the default administrator credentials:
- **Username:** `admin`
- **Password:** `admin123`

## Project Structure

- `backend/`: FastAPI application, Celery tasks, SQLAlchemy models, and database seeding scripts.
- `frontend/`: React components, pages, context, and Vite configuration.
- `diploma_artifacts/`: Supplementary academic materials, generated reports, and diagrams.

## Disclaimer
This software was developed for academic and demonstration purposes as part of a diploma project. All data generated in "Demonstration Mode" is synthetic and any resemblance to actual vulnerable infrastructure is illustrative.
