# API Reference

This document lists the endpoints provided by Secure User Management API. Live
Swagger UI: <https://mini-user-api.onrender.com/docs> (local:
`http://127.0.0.1:8002/docs`).

Authenticated routes need a JWT access token:

```text
Authorization: Bearer your_access_token
```

## Roles and permissions

Every user has one of four roles. Permissions are defined once in
`app/permissions.py`, enforced on every route, and returned by `GET /profile`
so clients can mirror them.

| Role | Value | Permissions |
| --- | --- | --- |
| Admin | `admin` | Everything below, plus `users:read` and `users:manage` |
| Manager | `manager` | `access_requests:submit`, `access_requests:review`, `activity:read_team` |
| Member | `member` | `access_requests:submit` |
| Viewer / Auditor | `viewer` | `activity:read_all`, `audit:read` (read-only) |

Access request, activity and audit permissions are reserved for upcoming
features; today only `users:read` / `users:manage` guard endpoints.

**Existing role values** are mapped when read; stored values are not
rewritten:

| Stored value | Treated as |
| --- | --- |
| `admin`, `Admin` (any case) | Admin |
| `user` (original standard account) | Member |
| `auditor` | Viewer / Auditor |
| anything else / empty | Member (least privilege) |

On input, `role` accepts the four values (any case) plus the aliases `user` and
`auditor`; anything else is rejected with `422`.

## Core endpoints

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/` | — | API root status |
| GET | `/health` | — | Health check |
| GET | `/ready` | — | Database readiness check |
| GET | `/docs` | — | Swagger UI |
| GET | `/openapi.json` | — | OpenAPI schema |

## Authentication

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| POST | `/login` | — | JSON `{username, password}` → `{access_token, token_type}` |
| POST | `/token` | — | Same, as an OAuth2 form (used by Swagger *Authorize*) |
| GET | `/profile` | any signed-in user | Current user and their permissions |
| POST | `/profile/password` | any signed-in user | Change own password |

Login returns `401 Invalid username or password` for unknown users, wrong
passwords and demo seed accounts, and `403 Account is deactivated` for a
deactivated account (only after the password has been verified).

Tokens are checked against the database on every request: deactivating or
deleting a user, or changing their role, takes effect immediately. Tokens
issued before this release (without a `uid` claim) remain valid until they
expire.

`GET /profile` response:

```json
{
  "message": "Protected profile access granted",
  "user": {
    "id": 12,
    "username": "jane.doe",
    "role": "admin",
    "is_active": true,
    "is_seed": false,
    "must_change_password": false,
    "permissions": ["access_requests:review", "...", "users:manage", "users:read"]
  }
}
```

`POST /profile/password` body: `{current_password, new_password}`. The new
password must be 12–72 bytes and different from the current one. A wrong
current password returns `400` (not `401`, so the session is not ended).

While `must_change_password` is `true`, every endpoint except `GET /profile`
and `POST /profile/password` returns `403 Password change required`.

## User management

All routes below require `users:manage` (Admin), except the two `GET` routes
which require `users:read` (Admin) — or, for `GET /users/{id}`, that the
caller is that user.

| Method | Endpoint | Description |
| --- | --- | --- |
| GET | `/users` | `{users: [User]}`, ordered by id |
| GET | `/users/{id}` | `{user: User}` |
| POST | `/users` | Create a user |
| PUT | `/users/{id}` | Update username and role |
| POST | `/users/{id}/deactivate` | Deactivate (the normal way to remove access) |
| POST | `/users/{id}/reactivate` | Reactivate |
| DELETE | `/users/{id}` | Permanently delete a **deactivated** user |

`User` object:

```json
{
  "id": 12,
  "username": "jane.doe",
  "role": "manager",
  "is_active": true,
  "is_seed": false,
  "must_change_password": true
}
```

### Create — `POST /users`

Body: `{username, role?, password?}` (`role` defaults to `member`). Usernames
are 3–50 characters: letters, numbers, `.`, `_`, `-`.

When `password` is omitted (recommended), the server generates a random
24-character temporary password and returns it **once**:

```json
{
  "message": "User created",
  "user": { "id": 12, "username": "jane.doe", "role": "manager", "...": "..." },
  "temporary_password": "<shown once>"
}
```

The response is sent with `Cache-Control: no-store`; the password is never
stored in plain text or logged. Admin-created accounts always start with
`must_change_password: true`. Duplicate usernames return
`400 Username already exists`.

### Safeguards

| Rule | Response |
| --- | --- |
| Changing your own role | `409 You can't change your own role` |
| Deactivating yourself | `409 You can't deactivate your own account` |
| Deleting yourself | `409 You can't delete your own account` |
| Deleting an active user | `409 Deactivate the user before deleting them permanently` |
| Demoting the last active admin | `409 Cannot remove the last active admin` |
| Deactivating the last active admin | `409 Cannot deactivate the last active admin` |

Demo seed accounts never count as "an active admin", because they cannot
sign in.

### Errors

| Status | Meaning |
| --- | --- |
| 400 | Business rule (duplicate username, wrong current password) |
| 401 | Missing, invalid or expired token, or account deactivated/deleted |
| 403 | Signed in but not allowed (missing permission, password change required) |
| 404 | User not found |
| 409 | Safeguard prevented the change (see above) |
| 422 | Validation error (FastAPI's standard `detail` list) |

## Public demo session

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/demo/session` | `{access_token, token_type}` for the `demo.guide` account |

Only available when the API runs with `APP_ENV=demo` (otherwise `404`). It
refuses with `503` while the database contains any non-demo (`is_seed:
false`) account, or when the demo hasn't been seeded. See the
[Setup Guide](./setup.md#isolated-public-demo).

## Breaking changes in this release

- `POST /users` previously allowed **anyone** to create an account with any
  role, and `GET/PUT/DELETE /users/{id}` had no authentication. They now
  require an Admin. Self-registration is no longer available.
- `DELETE /users/{id}` only works on deactivated users.
- `role` values returned by the API are canonical (`member` instead of
  `user`, `admin` instead of `Admin`).
- The API refuses to start without an explicit `SECRET_KEY` unless
  `APP_ENV` is `development` or `test`.
