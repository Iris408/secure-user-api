# Setup Guide

This document explains how to run Secure User Management API locally.

## Installation

Clone the repository:

```bash
git clone https://github.com/Iris408/secure-user-management-api
cd secure-user-management-api
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Environment Variables

Create a local `.env` file in the project root.

Example variables:

```env
DATABASE_URL=
SECRET_KEY=
APP_ENV=
```

| Variable | Notes |
| --- | --- |
| `SECRET_KEY` | Signs JWTs. **Required** unless `APP_ENV` is `development` or `test`: the API refuses to start without it, or with the old built-in default. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `APP_ENV` | `development`, `test`, `demo`, or unset/`production`. Unset is treated as production. |
| `DATABASE_URL` | PostgreSQL connection string. |

Never commit real `.env` files or production secrets to GitHub.

Recommended `.gitignore` entries:

```txt
.env
.venv/
__pycache__/
.pytest_cache/
*.pyc
```

## Docker Database Connection

When running with Docker Compose, the backend connects to PostgreSQL using the Docker service name `db`.

```env
DATABASE_URL=postgresql://postgres:postgres@db:5432/secure_user_api_db
```

Start the app with Docker Compose:

```bash
docker compose up --build
```

Local URLs:

```text
http://127.0.0.1:8002
http://127.0.0.1:8002/health
http://127.0.0.1:8002/ready
http://127.0.0.1:8002/docs
```

Restart containers:

```bash
docker compose down
docker compose up --build
```

If your system uses the older Docker Compose command:

```bash
docker-compose up --build
```

## Manual Local Database Connection

If Docker is not available, the project can be run manually.

When running the backend directly with Uvicorn, use `localhost` instead of `db`:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/secure_user_management_api_db
```

Make sure PostgreSQL is running locally and that `secure_user_management_api_db` has already been created.

Run the FastAPI server:

```bash
uvicorn app.main:app --reload --port 8002
```

## Schema Updates

On start-up the API runs `app/migrations.py`, which adds any missing columns
to an existing `users` table (`is_active`, `is_seed`, `must_change_password`).
It only adds columns with safe defaults — existing rows stay active and keep
their stored role values — and is safe to run repeatedly. The equivalent SQL,
if you prefer to apply it by hand before deploying:

```sql
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_seed BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
```

## Running Tests

This project uses pytest for backend testing. The test fixtures drop and
recreate tables, so they **refuse to run unless `DATABASE_URL` points to a
database whose name contains `test`**.

Run tests with Docker Compose against a separate test database:

```bash
docker compose up -d --build
docker compose exec db createdb -U postgres secure_user_api_test_db
docker compose exec \
  -e DATABASE_URL=postgresql://postgres:postgres@db:5432/secure_user_api_test_db \
  api pytest
```

Or against any disposable PostgreSQL instance:

```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5435/secure_user_api_test_db \
SECRET_KEY=test-secret-key python -m pytest
```

Test coverage includes:

- Health, readiness and OpenAPI endpoints
- The role/permission matrix and mapping of existing role values
- Authentication failures (missing, invalid and stale tokens, deactivated users)
- Authorization for every user-management route and role
- User lifecycle: create, temporary passwords, password change, update,
  deactivate, reactivate and delete, including self/last-admin safeguards
- Backwards compatibility of response shapes and pre-existing tokens
- Schema migration on a pre-existing table
- Demo seed data safeguards

## Demo Seed Data

`scripts/seed_demo_users.py` creates 124 synthetic users for demos and
screenshots:

```bash
APP_ENV=development python -m scripts.seed_demo_users           # create
APP_ENV=development python -m scripts.seed_demo_users --remove  # remove
```

Safeguards:

- Refuses to run unless `APP_ENV` is `development`, `test` or `demo`, and
  never on Render or against a `*.render.com` database.
- Accounts are named `demo.<first>.<last>` and flagged `is_seed`; the API
  returns `is_seed: true` so clients can label them.
- Seed accounts cannot sign in and never count as an active admin.
- `--remove` deletes only `is_seed` rows. Running the seed twice creates
  nothing new.

## Isolated Public Demo

The public demo must be a **separate deployment with its own database** —
never the production API or database:

1. Create a new database that contains no real accounts.
2. Run the API against it with `APP_ENV=demo` and a `SECRET_KEY` that is
   different from production (so demo tokens are useless in production).
3. Seed it: `APP_ENV=demo DATABASE_URL=... python -m scripts.seed_demo_users`.
   This adds the 124 synthetic users and the `demo.guide` account.
4. Point the frontend's `VITE_DEMO_API_URL` at this deployment.

`POST /demo/session` then issues a token for `demo.guide` without any
credentials. It returns `404` unless `APP_ENV=demo`, and `503` whenever the
database contains any non-demo account. Users created during a demo are
stored as demo data, and no demo account can sign in with a password.

The seed script refuses to run on Render or against a `*.render.com`
database. To host the demo database on Render, seed it from a workstation
through a non-Render hostname, or review and deliberately relax that guard;
it is intentionally not configurable.