# CI Notes

This document describes the automated checks for Secure User API. The
repository has Backend CI and Docker CI workflows. They run on pushes to
`main` and on pull requests targeting `main`.

## Backend CI

Backend CI uses Python 3.11 and a temporary PostgreSQL 15 service configured
with a separate test database. It installs the project dependencies and runs
Python syntax checks and the complete pytest suite.

The workflow sets test-only database and signing-key values. The test suite
refuses to run unless `DATABASE_URL` names a database containing `test`.

The checks run are:

```bash
python -m compileall app tests
python -m pytest -q
```

## Docker CI

Docker CI builds the Docker Compose services defined by the repository’s
Compose file. It fails if neither `docker-compose.yml` nor `compose.yml` is
present.

This verifies that the configured services can be built. It does not connect
to either hosted database or deploy the services.

## Running checks locally

Use a disposable PostgreSQL database whose name contains `test`. Never point
the test suite at a production or demo database: test fixtures drop and
recreate tables.

With Docker Compose running:

```bash
docker compose up -d --build
docker compose exec db createdb -U postgres secure_user_api_test_db
docker compose exec \
  -e DATABASE_URL=postgresql://postgres:postgres@db:5432/secure_user_api_test_db \
  api python -m pytest
```

To build the Compose services:

```bash
docker compose build
```

## Deployment

GitHub Actions validates code and builds containers; these workflows do not
deploy the API. The production and demo APIs are hosted separately on Render.
Check each Render service’s deployment status and health after changes are
merged or pushed to its configured deployment branch.

A green CI result confirms that the automated checks passed. It does not
confirm that a Render deployment is live, that startup completed, or that the
API can connect to its configured database.

## Maintenance

Keep the workflows aligned with the project’s actual Python version,
dependencies, test database safeguards and Compose configuration. Update this
document when workflow commands or deployment arrangements change.