[![Django CI](https://github.com/Drakon4ik-Coder/okta-dashboard-back/actions/workflows/django.yml/badge.svg)](https://github.com/Drakon4ik-Coder/okta-dashboard-back/actions/workflows/django.yml)
[![Docker CI](https://github.com/Drakon4ik-Coder/okta-dashboard-back/actions/workflows/docker.yml/badge.svg)](https://github.com/Drakon4ik-Coder/okta-dashboard-back/actions/workflows/docker.yml)

# Okta Dashboard Backend

## Overview
Okta Dashboard Backend is a Django service that powers internal security dashboards. It ingests Okta system logs, stores analytics data in MongoDB, exposes REST APIs for metrics and forensics, and provides Okta OIDC-based authentication for the web UI.

## Key Features
- Okta OIDC login flow with session management and logout handling.
- DPoP-enabled Okta System Log ingestion with MongoDB storage.
- Security analytics and forensics APIs built on Django REST Framework.
- Zero-trust middleware for continuous auth and API authorization.
- Background scheduling with Django Q backed by Redis.
- Prometheus metrics endpoint and optional Grafana dashboards via Docker Compose.

## Architecture
- Django 5 app with multiple domain apps under `apps/`.
- MongoDB (via MongoEngine) for Okta log and analytics data.
- SQLite for Django core models by default (configurable via `DJANGO_DB_*`).
- Redis for task queues and caching.
- Prometheus + Grafana stack for metrics (Docker Compose).

## Project Structure
- `apps/api/` - REST API routes and viewsets.
- `apps/authentication/` - Zero-trust auth middlewares and services.
- `apps/login_tracking/` - Login time tracking and metrics.
- `apps/okta_auth/` - Okta OIDC login and middleware.
- `apps/traffic_analysis/` - Log ingestion, analytics, and dashboards.
- `config/` - Django settings, URLs, WSGI/ASGI.
- `okta_dashboard/` - Shared site app and middleware.
- `start_all.py` - Runs server + Django Q cluster + scheduler.
- `run_asgi.py` - Starts ASGI server with Uvicorn.

## Requirements
- Python 3.10+ (CI uses 3.10)
- MongoDB 5+ (Mongo 8 in Docker)
- Redis 7+
- Docker + Docker Compose (optional)

## Configuration
Configuration is loaded from environment variables or a local `.env` file. Docker can also read secrets from `/run/secrets/django_secret_key`.

Common variables:
- `DJANGO_SECRET_KEY` - Required for Django security.
- `DEBUG` - Set to `True` for local development.
- `DJANGO_ALLOWED_HOSTS` - Comma-separated hosts list.
- `DJANGO_DB_ENGINE`, `DJANGO_DB_NAME` - Database override (defaults to SQLite).
- `MONGO_HOST`, `MONGO_PORT`, `MONGO_DB_NAME` - MongoDB settings.
- `MONGO_USER`, `MONGO_PASSWORD`, `MONGO_AUTH_SOURCE` - MongoDB auth settings.
- `MONGODB_URL` - Full MongoDB URI (overrides individual settings if set).
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD` - Redis settings.
- `OKTA_ORG_URL`, `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET` - Okta log ingestion.
- `OKTA_AUTHORIZATION_ORG_URL`, `OKTA_AUTHORIZATION_CLIENT_ID`, `OKTA_AUTHORIZATION_CLIENT_SECRET` - Okta OIDC login.

Minimal `.env` example for Docker:

```env
DJANGO_SECRET_KEY=replace-me
DEBUG=0
DJANGO_SETTINGS_MODULE=config.settings
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,web

MONGO_USER=admin
MONGO_PASSWORD=admin
MONGO_DB_NAME=OktaDashboardDB
MONGO_AUTH_SOURCE=admin

REDIS_PASSWORD=redis

# Okta (optional for local UI; required for log ingestion)
OKTA_ORG_URL=https://your-domain.okta.com
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret

OKTA_AUTHORIZATION_ORG_URL=https://your-auth-domain.okta.com
OKTA_AUTHORIZATION_CLIENT_ID=your-auth-client-id
OKTA_AUTHORIZATION_CLIENT_SECRET=your-auth-client-secret
```

## DPoP Keys
Okta DPoP flows expect a registered RSA key pair. Place the following files in `keys/`:
- `keys/private_key.pem`
- `keys/public_key.jwk`

If the keys are missing, the app will generate new keys at runtime, but Okta will reject them unless they are registered in your Okta application.

## Local Development (No Docker)
1. Create a virtual environment: `python3 -m venv .venv && source .venv/bin/activate`
2. Install dependencies: `pip install -r requirements.txt`
3. Create `.env` with the required variables.
4. Run migrations: `python manage.py migrate`
5. Start the server: `python manage.py runserver`
6. Optional: start background workers with `python manage.py qcluster` or run everything with `python start_all.py`.

## Docker Quick Start
1. Create `.env` at the project root (see example above).
2. Build and start services:
   `docker compose up -d --build`
3. Check health: `curl http://localhost:8000/health/`
4. Access dashboards:
   - App: `http://localhost:8000/`
   - Swagger: `http://localhost:8000/docs/`
   - Redoc: `http://localhost:8000/redoc/`
   - Prometheus: `http://localhost:9090/`
   - Grafana: `http://localhost:3000/`

## Background Jobs and Okta Log Ingestion
- Manual ingestion: `python manage.py fetch_okta_logs_dpop --minutes 15 --limit 1000`
- Scheduled ingestion: `python manage.py qcluster` (or `python start_all.py` for dev)

## API and Monitoring Endpoints
- Health check: `/health/`
- Metrics: `/metrics/`
- API base: `/api/v1/`
- API docs: `/api/docs/`
- API schema: `/api/schema/`

## Testing
- Django tests: `python manage.py test`
- Pytest (optional): `pytest`

## Notes
- MongoDB connectivity is best-effort at startup; the app logs a warning and retries on first access.
- When running Docker Compose, MongoDB and Redis are configured with auth by default.
