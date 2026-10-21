![Backend CI](https://github.com/Iris408/secure-user-management-api/actions/workflows/backend-ci.yml/badge.svg)
![Docker CI](https://github.com/Iris408/secure-user-management-api/actions/workflows/docker-ci.yml/badge.svg)

# Secure User Management API

A production-style FastAPI backend for secure user management, JWT authentication, role-based access control and PostgreSQL persistence.

## Live Demo

JWT backend deployed on Render:

- [Root Endpoint](https://mini-user-api.onrender.com)
- [Health Check](https://mini-user-api.onrender.com/health)
- [Readiness Check](https://mini-user-api.onrender.com/ready)
- [Swagger API Docs](https://mini-user-api.onrender.com/docs)

## Current Status

| Area | Status | Area | Status |
| --- | --- | --- | --- |
| FastAPI backend | ✅ Complete | Docker support | ✅ Complete |
| PostgreSQL database | ✅ Connected | Render deployment | ✅ Live |
| SQLAlchemy ORM | ✅ Complete | Swagger API documentation | ✅ Available |
| JWT authentication | ✅ Working | Backend tests | ✅ Auth, roles and user lifecycle |
| Password hashing | ✅ Working | Backend CI | ✅ Passing |
| Role-based access control | ✅ Working | Docker CI | ✅ Passing |


## Features

- JWT authentication, checked against the database on every request
- Four-role access control: Admin, Manager, Member, Viewer / Auditor
- Admin user management: create, edit, deactivate, reactivate and delete
- One-time temporary passwords with a required change at first sign-in
- Safeguards against self-lockout and removing the last admin
- Organisation settings for Admins: organisation name, timezone, access
  request policy (on/off and which non-Admin roles can be requested) and
  session length, validated and enforced by the API and audited
- Organisation activity feed (`GET /activity`): sign-ins and access events
  for Admins, Managers and Viewers / Auditors by default, without the audit
  log's internal detail
- Configurable role permissions: Admins choose what Managers, Members and
  Viewers / Auditors may do, within fixed safeguards (Admin keeps full
  access; user management, the audit log and the policy itself stay
  Admin-only). Enforced by the API on every request and audited
- Access requests: members and managers ask for a role change, managers and
  admins approve or decline it, with full decision history
- Append-only audit log of sign-ins and administrative changes, readable by
  admins through `GET /audit-events`
- Synthetic demo seed data, blocked outside development/test/demo; Render
  seeding only for the dedicated demo database with explicit opt-ins
  ([Setup Guide](./docs/setup.md#seeding-the-demo-database-on-render))
- PostgreSQL persistence
- SQLAlchemy ORM
- Docker Compose development environment
- Automated testing with pytest
- Continuous integration with GitHub Actions

## Tech Stack

| Area | Technologies |
| --- | --- |
| Backend | Python, FastAPI, SQLAlchemy, Uvicorn |
| Database | PostgreSQL |
| Authentication | JWT, OAuth2, bcrypt password hashing |
| Testing | pytest |
| DevOps / Tooling | Docker, Docker Compose, GitHub Actions, Render, Git, GitHub |

## Screenshots

| Swagger API Docs | GitHub Actions CI | Render Deployment |
| --- | --- | --- |
| ![Swagger API Docs](screenshots/01-swagger-docs.png) | ![GitHub Actions CI](screenshots/05-github-actions-ci.png) | ![Render Deployment](screenshots/06-render-deployment.png) |

## Quick Start

Clone the repository:

```bash
git clone https://github.com/Iris408/secure-user-management-api
cd secure-user-management-api
```

Run with Docker Compose:

```bash
docker compose up --build
```

Local API:

```text
http://127.0.0.1:8002
```

Swagger Docs:

```text
http://127.0.0.1:8002/docs
```

Run tests (against a separate test database — see the [Setup Guide](./docs/setup.md#running-tests)):

```bash
docker compose exec db createdb -U postgres secure_user_api_test_db
docker compose exec \
  -e DATABASE_URL=postgresql://postgres:postgres@db:5432/secure_user_api_test_db \
  api pytest
```

## Roles

| Role | Can |
| --- | --- |
| Admin | Manage users, roles and role permissions; read the audit log; decide every access request |
| Manager | Decide Member and Viewer / Auditor access requests; view organisation activity |
| Member | Use the service; submit access requests and see their own |
| Viewer / Auditor | Read-only: view organisation activity; no user management or request decisions |

Existing `admin` accounts stay Admins and existing `user` accounts become
Members. These are the defaults: Admins can let Managers, Members or
Viewers / Auditors view the user directory, and adjust who submits and reviews
access requests and who sees activity, within the fixed safeguards. See the
[API Reference](./docs/api-reference.md#roles-and-permissions) for the
permission matrix, endpoints and the breaking changes in this release.

## Documentation

For more detailed project documentation this is available in the `docs/` folder.

| Document | Description |
| --- | --- |
| [Setup Guide](./docs/setup.md) | Environment variables, Docker setup, manual setup, and test commands |
| [API Reference](./docs/api-reference.md) | Main API endpoints and route notes |
| [Auth Flow](./docs/auth-flow.md) | JWT authentication, roles, account lifecycle and temporary passwords |
| [Project Details](./docs/projects-details.md) | Architecture, limitations, future improvements, and learning notes |
| [CI/CD Notes](./docs/ci-cd.md) | Backend CI and Docker CI workflow notes |

## Project Summary

Secure User Management API is a backend portfolio project built to practise real API development skills: user authentication, JWT token handling, role-based access control, PostgreSQL persistence, Dockerized development, health checks, testing, deployment, and CI/CD validation.

## License
This project is licensed under the terms in [MIT LICENSE](./LICENSE) file for details.

## Author

Built by [Iris408](https://github.com/Iris408)