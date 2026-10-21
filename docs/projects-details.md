# Project Details

This document describes the architecture, responsibilities and current
maintenance scope of Secure User API.

## Architecture

```text
AccessHub frontend
        │ HTTPS
        ▼
FastAPI application
        │
        ├── Authentication, permissions and business rules
        ├── SQLAlchemy models and database sessions
        └── PostgreSQL
```

The backend is maintained separately from the React and TypeScript AccessHub
frontend. The production API and public demo API are separate Render services
with separate database configurations. The demo uses `APP_ENV=demo` and a
dedicated demo database.

## Backend responsibilities

The API is built with FastAPI and organized into route, model and policy
modules. It is responsible for:

- Validating API input and responses
- Authenticating users and issuing JWT access tokens
- Hashing passwords and enforcing temporary-password changes
- Checking current accounts, roles and permissions against the database
- Managing users and their account lifecycle
- Handling access requests and role decisions
- Enforcing configurable role permissions and organisation settings
- Recording Activity and append-only Audit Log events
- Providing health, readiness and OpenAPI documentation endpoints

Authorization is enforced by the API on every request. Frontend visibility
rules are for usability and do not replace server-side checks.

## Database

PostgreSQL stores users, access requests, role permission grants, organisation
settings and audit events. SQLAlchemy defines models and manages database
sessions.

On startup, the application creates missing schema structures and adds
default policy and settings rows without overwriting existing choices. Audit
events are append-only; PostgreSQL triggers reject attempts to update, delete
or truncate them.

The test suite must use a disposable database whose name contains `test`.
Fixtures drop and recreate tables, and refuse to run against a database with
a different name.

## Authentication and authorization

The API uses bcrypt password hashes and signed JWT access tokens. Each
authenticated request reloads the account and current permissions from the
database, so account deactivation, role changes and permission changes take
effect on the next request.

The four supported roles are Admin, Manager, Member and Viewer / Auditor.
Admins retain all permissions. They can configure selected permissions for
other roles within fixed safeguards. The API also enforces role-based rules
for access request decisions, the Audit Log, role configuration and Settings.

See the [Auth Flow](./auth-flow.md) and
[API Reference](./api-reference.md) for endpoint and policy details.

## Demo behavior

The public demo uses the separate demo API and database. `POST /demo/session`
starts a session as `adminDemoUser` without a password. Seeded accounts cannot
sign in with passwords.

The demo is shared, so visitors can change users, role permissions and
Settings, and submit or decide access requests. Activity and Audit Log pages
show real events created by demo use rather than fabricated event history.

A repeatable demo reset procedure is planned maintenance. It should restore
demo users, permission defaults, organisation settings and seeded requests,
and define how to handle append-only Audit Log records and real Activity
events. The reset process is not implemented