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

### Audit log table

On start-up `Base.metadata.create_all` creates the `audit_events` table if it
doesn't exist, and `ensure_audit_log_append_only` (in `app/migrations.py`) adds
PostgreSQL triggers that reject `UPDATE`, `DELETE` and `TRUNCATE` on it. Both
steps are additive and idempotent; existing users are not touched and no
historical events are invented — the log starts empty and fills as people use
the API.

Operational notes:

- **Retention:** events are kept indefinitely. There is no cleanup job, and the
  triggers deliberately block deletion; a future retention policy needs a
  reviewed migration that adjusts the triggers first.
- **Volume:** every sign-in attempt, including failed ones, adds a row. There
  is no rate limiting yet, so a password-guessing attack also grows the table.
- **Personal data:** deleted users' usernames remain in past events as part of
  the history.
- **Demo:** no synthetic audit history is seeded anywhere. A demo deployment's
  log contains only real activity in that demo (for example demo sessions).

### Access requests table

`Base.metadata.create_all` also creates the `access_requests` table and its
partial unique index `uq_access_requests_one_pending_per_user` (one pending
request per user) on start-up if they don't exist. This is additive: existing
tables and users are unchanged and the table starts empty — no request
history is invented outside the demo seed. The equivalent SQL for applying it
by hand is the table definition in `app/models/access_request_model.py` plus:

```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_access_requests_one_pending_per_user
  ON access_requests (requester_id) WHERE status = 'pending';
```

Requests store snapshots (username and role at submission, reviewer username
and role) rather than foreign keys, so history survives renames and account
deletion. Reasons and decision notes are kept indefinitely, like audit events.

### Role permissions table

On start-up `Base.metadata.create_all` creates the `role_permission_grants`
table, and `ensure_role_permission_defaults` (in `app/migrations.py`) adds one
row for each configurable (role, permission) cell that doesn't have one yet,
using the default policy:

| Role | `users:read` | `access_requests:submit` | `access_requests:review` | `activity:read` |
| --- | --- | --- | --- | --- |
| Manager | off | on | on | on |
| Member | off | (always on, not stored) | off | off |
| Viewer / Auditor | off | (never, not stored) | (never, not stored) | on |

Cells added by a later release (such as `activity:read`) are inserted the
same way on the next start-up, with their default value.

This preserves everyone's effective access. It is additive and idempotent:
existing rows (an Admin's choices) are never overwritten, and no user,
password, role, access request or audit event is touched. A missing row
falls back to the default, so the API also behaves correctly before the
defaults are inserted. Equivalent SQL, if you prefer to apply it by hand:

```sql
CREATE TABLE IF NOT EXISTS role_permission_grants (
  role VARCHAR(16) NOT NULL,
  permission VARCHAR(64) NOT NULL,
  granted BOOLEAN NOT NULL,
  updated_at TIMESTAMPTZ,
  updated_by_id INTEGER,
  updated_by_username VARCHAR,
  PRIMARY KEY (role, permission)
);
INSERT INTO role_permission_grants (role, permission, granted) VALUES
  ('manager', 'users:read', false),
  ('member', 'users:read', false),
  ('viewer', 'users:read', false),
  ('manager', 'access_requests:submit', true),
  ('manager', 'access_requests:review', true),
  ('member', 'access_requests:review', false),
  ('manager', 'activity:read', true),
  ('member', 'activity:read', false),
  ('viewer', 'activity:read', true)
ON CONFLICT (role, permission) DO NOTHING;
```

To return to the defaults, an Admin saves the default matrix on the Roles
page (each change is audited). The demo seed doesn't touch this table.

### Organisation settings table

On start-up `Base.metadata.create_all` creates the single-row
`organisation_settings` table, and `ensure_settings_row` (in
`app/migrations.py`) inserts the defaults if the row is missing: no
organisation name, viewers' own timezone, access requests on for Manager,
Member and Viewer / Auditor, and 30-minute sessions — exactly how the API
behaved before. An existing row (an Admin's saved settings) is never changed,
and no user, grant, request or audit event is touched. Nothing is seeded
beyond that row. Equivalent SQL:

```sql
CREATE TABLE IF NOT EXISTS organisation_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  organisation_name VARCHAR(80),
  timezone VARCHAR(64),
  access_requests_enabled BOOLEAN NOT NULL,
  requestable_roles VARCHAR(64) NOT NULL,
  session_minutes INTEGER NOT NULL,
  revision INTEGER NOT NULL,
  updated_at TIMESTAMPTZ,
  updated_by_id INTEGER,
  updated_by_username VARCHAR
);
INSERT INTO organisation_settings
  (id, access_requests_enabled, requestable_roles, session_minutes, revision)
VALUES (1, true, 'manager,member,viewer', 30, 0)
ON CONFLICT (id) DO NOTHING;
```

Timezones are validated against the server's IANA timezone database (Python
`zoneinfo`). The Docker image (`python:3.11`) and Render's Python runtime
include it; on a system without one, every timezone is refused until the
`tzdata` package is installed, and the "viewer's own timezone" default keeps
working.

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
- Audit events: recording, redaction of credentials, admin-only access,
  filters, pagination and append-only enforcement (API and database)

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
- It also adds 24 deterministic synthetic access requests between demo users
  (10 approved, 6 declined, 8 pending), flagged `is_seed`. Approved requests
  match the seeded users' roles, so the role distribution is unchanged.
  Manager requests are always decided by a demo admin. No audit events are
  seeded. `--remove` deletes these requests first.

## Isolated Public Demo

The public demo must be a **separate deployment with its own database** —
never the production API or database:

1. Create a new, empty database for the demo only (for example
   `accesshub_demo`). It must contain no real accounts.
2. Run the demo API against it with `APP_ENV=demo` and a `SECRET_KEY` that is
   different from production, so demo tokens are useless in production.
3. Seed it (see below). This adds the 124 synthetic users and the
   `adminDemoUser` demo admin, all with `is_seed=true`.
4. Point the frontend's `VITE_DEMO_API_URL` at the demo deployment.

`POST /demo/session` then issues a token for `adminDemoUser` without any
credentials. It returns `404` unless `APP_ENV=demo`, and `503` whenever the
database contains any non-seed account. Users created during a demo are
stored as demo data, and no seed account — including `adminDemoUser` — can
sign in with a password.

### Seeding the demo database on Render

The seed script **refuses Render targets by default** (when the `RENDER`
environment variable is set or the database host ends in `.render.com`). The
dedicated demo database can only be seeded when every one of these opt-ins is
present:

| Requirement | How |
| --- | --- |
| Demo environment | `APP_ENV=demo` |
| Explicit opt-in | `--allow-render-demo` |
| The intended database | `--expected-database <name>` must equal `SELECT current_database()` |
| No real accounts | The database must contain no non-seed user rows (checked automatically; on a legacy table without `is_seed`, every row counts as real) |

Safe command — use the **demo** database's connection string, never
production's:

```bash
APP_ENV=demo \
DATABASE_URL='<demo database external URL>' \
python -m scripts.seed_demo_users --allow-render-demo --expected-database accesshub_demo
```

The database name and the real-account check are verified before any table
is created or row written; if either fails, the script stops with exit code
2 and changes nothing. It only ever creates `demo.*` users and
`adminDemoUser`, skips names that already exist, refuses if a real account is
already called `adminDemoUser`, and never modifies other accounts such as
`adminuser` or `testuser`. Re-running it creates nothing new.

To remove the demo data from that database, add `--remove` to the same
command; only `is_seed` rows are deleted.

## Shared demo maintenance and reset

The public demo is shared, so visitors can change its users, permissions,
settings and access requests. There is no automatic reset procedure yet.

The seed command is safe to rerun, but it does **not** restore the demo to its
original state. Its `--remove` option deletes only seeded users and seeded
requests; it does not reset saved role permissions or organisation settings,
and it does not remove audit events.

A reset procedure is planned maintenance. It should be tested against a
throwaway copy first and should restore the intended demo users,
`adminDemoUser`, role permission defaults, organisation settings and synthetic
access requests. It must define how to handle the append-only Audit Log and
real Activity events, rather than silently replacing real history with
fabricated events.

Until a reset process is implemented and reviewed, do not treat the seed
command as a full reset. Any manual recovery must be deliberate, verified
against the dedicated demo database, and kept separate from production.
