# API Reference

This document lists the endpoints provided by Secure User Management API. Live
Swagger UI: <https://mini-user-api.onrender.com/docs> (local:
`http://127.0.0.1:8002/docs`).

Authenticated routes need a JWT access token:

```text
Authorization: Bearer your_access_token
```

## Roles and permissions

Every user has one of four roles: Admin, Manager, Member and Viewer / Auditor.
There are no custom roles. What each role may do is a **policy** that Admins
can partly configure (see [Role permissions](#role-permissions)). It is
resolved centrally (`app/policy.py`) on every request from the persisted
policy and the user's current database role — never from token claims — and
returned by `GET /profile` as `permissions`, so clients can mirror it.

Default policy (the access people had before permissions became configurable):

| Role | Value | Default permissions |
| --- | --- | --- |
| Admin | `admin` | All of them, always (not configurable) |
| Manager | `manager` | `access_requests:submit`, `access_requests:review`, `activity:read` |
| Member | `member` | `access_requests:submit` |
| Viewer / Auditor | `viewer` | `activity:read` (read-only) |

| Permission | Guards |
| --- | --- |
| `users:read` | `GET /users`, other users' `GET /users/{id}` |
| `users:manage` | Creating, editing, deactivating, reactivating and deleting users (Admin only) |
| `access_requests:submit` | `POST /access-requests` |
| `access_requests:review` | The access request summary, queue, approve and decline |
| `audit:read` | `GET /audit-events` (Admin only) |
| `roles:manage` | `GET`/`PUT /role-permissions` (Admin only) |
| `settings:manage` | `GET`/`PUT /settings` (Admin only) |
| `activity:read` | `GET /activity` (the organisation activity feed) |

Some rules are tied to the Admin **role** and apply whatever the policy says:
only Admins decide requests for Manager access, nobody decides their own
request, Admins can't submit access requests, and `/audit-events` and
`/role-permissions` also check the role.

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

## Audit log

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/audit-events` | Admin (role checked in the database) | Read-only list of audit events, newest first |

There are no endpoints to create, edit or delete audit events: the API records
them itself, and on PostgreSQL a trigger rejects `UPDATE`, `DELETE` and
`TRUNCATE` on the table. `audit:read` is Admin-only and can't be granted to
another role, and the endpoint also checks the Admin role; other callers get
`403` (and an `access.denied` event).

Query parameters (all optional):

| Parameter | Description |
| --- | --- |
| `event_type` | One event type from the table below (`422` if unknown) |
| `outcome` | `success`, `failure` or `denied` |
| `q` | Actor or target username contains (case-insensitive; `%`/`_` are literal) |
| `since` / `until` | ISO 8601 timestamps; `since` inclusive, `until` exclusive (`400` if `since >= until`) |
| `page` / `page_size` | 1-based page, `page_size` 1–100 (default 25) |

Response:

```json
{
  "events": [
    {
      "id": 42,
      "occurred_at": "2026-10-20T09:30:00.123456+00:00",
      "event_type": "user.role_changed",
      "outcome": "success",
      "actor": { "id": 1, "username": "jane.admin", "role": "admin" },
      "target": { "type": "user", "id": 7, "username": "sam.lee" },
      "details": { "from_role": "member", "to_role": "viewer" }
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 25
}
```

`actor` is `null` when nobody was signed in (e.g. a failed sign-in); `target`
is `null` when no account was affected. Actor and target are snapshots taken
when the event happened, so they survive renames and deletion.

### Recorded events

| `event_type` | Outcomes | Recorded when | `details` |
| --- | --- | --- | --- |
| `auth.sign_in` | success, failure | `POST /login` or `/token` | `method` (`password`, `oauth2_form`); `reason` on failure (`invalid_credentials`, `account_deactivated`) |
| `auth.password_changed` | success, failure | `POST /profile/password` | `reason` on failure (`incorrect_current_password`, `password_unchanged`) |
| `auth.demo_session` | success, denied | `POST /demo/session` (demo deployments) | `method`, or `reason: real_accounts_present` |
| `user.created` | success | `POST /users` | `role`, `password_generated` |
| `user.updated` | success | Username changed via `PUT /users/{id}` | `from_username`, `to_username` |
| `user.role_changed` | success, denied | Role changed via `PUT /users/{id}` | `from_role`, `to_role`; or `reason` (`own_role`, `last_active_admin`) |
| `user.deactivated` | success, denied | `POST /users/{id}/deactivate` | `reason` when denied (`own_account`, `last_active_admin`) |
| `user.reactivated` | success | `POST /users/{id}/reactivate` | — |
| `user.deleted` | success, denied | `DELETE /users/{id}` | `role`; or `reason` (`own_account`, `still_active`) |
| `access_request.submitted` | success | `POST /access-requests` | `request_id`, `requested_role`, `role` (role at submission) |
| `access_request.approved` | success, denied | `POST /access-requests/{id}/approve` | `request_id`, `requested_role`; `reason` when denied (`own_request`, `manager_requires_admin`) |
| `access_request.declined` | success, denied | `POST /access-requests/{id}/decline` | Same as approved |
| `role.permissions_changed` | success | `PUT /role-permissions` changed a role | `role`, `from_permissions`, `to_permissions` (comma-separated permission codes; `""` for none). `target` is `{"type": "role", "id": null, "username": "<role>"}` |
| `settings.changed` | success | `PUT /settings` changed a setting | `setting`, `from_value`, `to_value` (display text: `on`/`off`, comma-separated roles, minutes, or `""` for not set) |
| `access.denied` | denied | A signed-in user calls a route their permissions don't allow | `permission`, `action` (route template, e.g. `POST /users/{user_id}/deactivate`), `reason` |

Routine reads (`GET /profile`, `GET /users`, `GET /audit-events`), validation
errors (`422`) and invalid or expired tokens (`401`) are not recorded.

### What is never stored

Passwords, temporary passwords, JWTs and keys are never written to audit
records, and neither are access request reasons or decision notes (they stay
on the request itself): `details` only accepts an allow-list of keys with short, simple
values. A failed sign-in for an unknown username stores no username at all,
because the typed text could be a password entered in the wrong field.

## Access requests

A user asks for their role to change to Manager, Member or Viewer / Auditor.
Admin can never be requested, and admins cannot submit requests (they already
have full access).

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| POST | `/access-requests` | `access_requests:submit` (Member, Manager) | Submit a request; `201` with `{request}` |
| GET | `/access-requests/mine` | Any active user | The caller's own requests, newest first (`page`, `page_size`) |
| GET | `/access-requests/summary` | `access_requests:review` (Manager, Admin) | `{pending_total, recent}` — the 5 newest pending requests |
| GET | `/access-requests` | `access_requests:review` | Queue and history, newest first, with filters |
| POST | `/access-requests/{id}/approve` | `access_requests:review` | Approve; changes the requester's role. Body `{"note": "…"}` (optional) |
| POST | `/access-requests/{id}/decline` | `access_requests:review` | Decline; the role is unchanged. Same body |

Submission body: `{"requested_role": "manager" | "member" | "viewer", "reason": "…"}`.
`reason` is 3–500 characters after trimming; `note` is at most 500.

Filters for `GET /access-requests` (all optional):

| Parameter | Description |
| --- | --- |
| `status` | `pending`, `approved` or `declined` |
| `requested_role` | `manager`, `member` or `viewer` |
| `q` | Requester username contains (case-insensitive; `%`/`_` are literal) |
| `since` / `until` | Submission time, ISO 8601; `since` inclusive, `until` exclusive (`400` if `since >= until`) |
| `page` / `page_size` | 1-based page, `page_size` 1–100 (default 25) |

A request:

```json
{
  "id": 25,
  "status": "approved",
  "requested_role": "viewer",
  "reason": "I review the quarterly access audit.",
  "submitted_at": "2026-10-20T11:11:01.331690+00:00",
  "is_seed": false,
  "requester": {
    "id": 3, "username": "jane.doe", "role_at_submission": "member",
    "current_username": "jane.doe", "current_role": "viewer"
  },
  "decision": {
    "decided_at": "2026-10-20T11:14:00+00:00",
    "note": "Approved for Q4.",
    "reviewer": { "id": 2, "username": "maria.manager", "role": "manager" }
  },
  "can_decide": false,
  "decision_block_reason": "not_pending"
}
```

`username`, `role_at_submission` and the reviewer fields are snapshots taken
at submission/decision time; `current_username` / `current_role` are `null`
once the account is deleted. `decision` is `null` while pending.
`can_decide` and `decision_block_reason` (`missing_permission`,
`own_request`, `manager_requires_admin`, `not_pending`) tell clients whether
the caller may decide it; the API enforces the same rules.

### Rules

- One pending request per user (`409`), enforced by a partial unique index as
  well as in code. Requesting your current role is `400`.
- Managers may decide Member and Viewer / Auditor requests; only admins may
  decide Manager requests (`403`). Nobody can decide their own request
  (`403`). Both refusals are recorded as a `denied` approve/decline event.
  Callers without the permission get `403` and an `access.denied` event.
- A request is decided once. Deciding an already-decided request is `409`
  (`This access request has already been approved|declined`); the request
  row is locked during a decision, so concurrent decisions can't both win.
- Approval re-checks the requester and is refused with `409` if the account
  was deleted, deactivated or has since become an admin.
- Approval updates the role, the request and the audit events in one
  transaction; any failure rolls all of it back. Decline never changes the
  role.
- The submitted role and reason are never edited.

## Activity

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/activity` | `activity:read` (default: Admin, Manager, Viewer / Auditor) | Organisation sign-ins and access events, newest first |

The feed is a read-only view of the events the API already records (see
[Recorded events](#recorded-events)); every recorded event type appears.
Nothing is recorded for reading it, and routine reads are never events. It is
deliberately smaller than the audit log, which stays Admin-only:

| | `/activity` | `/audit-events` |
| --- | --- | --- |
| Who | `activity:read` (configurable) | Admin only |
| Actor / target | Username and role / type and username | Also account IDs |
| `details` | `reason`, `role`, `from_role`, `to_role`, `requested_role`, `from_username`, `to_username`, `permission`, `from_permissions`, `to_permissions` | All recorded fields, including `action` (route), `method`, `request_id`, `password_generated` |

Query parameters are the same as for `/audit-events`: `event_type`,
`outcome`, `q` (actor or target username contains), `since` / `until`
(`400` if `since >= until`), `page`, `page_size` (1–100, default 25).

Response:

```json
{
  "events": [
    {
      "id": 42,
      "occurred_at": "2026-10-20T09:30:00.123456+00:00",
      "event_type": "access.denied",
      "outcome": "denied",
      "actor": { "username": "sam.lee", "role": "member" },
      "target": null,
      "details": { "permission": "users:read", "reason": "missing_permission" }
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 25
}
```

`actor` is `null` when nobody was signed in (a failed sign-in); a failed
sign-in for an unknown username has no target either.

**Coverage.** Recorded: successful and failed sign-ins (and demo sessions),
password changes, user creation, renames, role changes, deactivation,
reactivation and deletion, permission denials and safeguard refusals,
access request submissions and decisions, and role permission changes. Not
recorded: routine reads, sign-outs (signing out only discards the token in
the browser; there is no server call), expired or invalid tokens, and
validation errors.

## Organisation settings

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/settings` | Admin (`settings:manage` and the Admin role) | All settings, revision, last change and limits |
| PUT | `/settings` | Admin | Replace all settings |
| GET | `/organisation` | Any active signed-in user | Name, timezone and access request policy |

Other callers of `/settings` get `403` and an `access.denied` event.

| Setting | Default | Effect |
| --- | --- | --- |
| `organisation_name` | `null` | Shown to signed-in users (sidebar). 0–80 characters, no control characters; empty becomes `null` |
| `timezone` | `null` | IANA name (e.g. `Europe/London`) used by the interface for dates, times, day groups and date filters; `null` = each viewer's own timezone. Must exist in the server's timezone database |
| `access_requests_enabled` | `true` | When `false`, `POST /access-requests` returns `403` "Access requests are turned off". Pending requests can still be decided |
| `requestable_roles` | `["manager", "member", "viewer"]` | `POST /access-requests` returns `400` "This role can't be requested" for any other role. `admin` is always rejected (`422`); at least one role is required while requests are enabled |
| `session_minutes` | `30` | Lifetime of tokens issued by `/login`, `/token` and `/demo/session`, 15–720. Tokens keep the expiry they were issued with, so a change applies to new sessions only |

The defaults match how the API behaved before settings existed. Settings only
narrow access requests; they never change who can approve them (only Admins
decide Manager requests, nobody decides their own).

`PUT` body — every setting plus the `revision` from `GET` (unknown fields are
refused):

```json
{
  "revision": 0,
  "organisation_name": "Acme Ltd",
  "timezone": "Europe/London",
  "access_requests_enabled": true,
  "requestable_roles": ["member", "viewer"],
  "session_minutes": 120
}
```

Responses: `200` with the saved settings (`revision` increases when anything
changed); `422` for any invalid value (the message names it; nothing is
saved); `409` when `revision` is out of date. All values and their audit
events are written in one transaction. Each changed setting records one
`settings.changed` event; saving unchanged settings records nothing.

`GET /organisation` response:

```json
{
  "organisation_name": "Acme Ltd",
  "timezone": "Europe/London",
  "access_requests": { "enabled": true, "requestable_roles": ["member", "viewer"] }
}
```

## Role permissions

| Method | Endpoint | Auth | Description |
| --- | --- | --- | --- |
| GET | `/role-permissions` | Admin (`roles:manage` and the Admin role) | The permission matrix |
| PUT | `/role-permissions` | Admin | Replace the configurable part of the matrix |

Other callers get `403` and an `access.denied` event.

Only these cells can be changed; every other cell is fixed:

| Permission | Configurable for | Fixed elsewhere because |
| --- | --- | --- |
| `users:read` | Manager, Member, Viewer / Auditor | — |
| `access_requests:submit` | Manager | Members always keep it; Viewer / Auditor is read-only |
| `access_requests:review` | Manager, Member | Viewer / Auditor is read-only |
| `activity:read` | Manager, Member, Viewer / Auditor | — |
| `users:manage`, `roles:manage`, `settings:manage` | — | Admin only (managing accounts includes assigning the Admin role) |
| `audit:read` | — | The audit log is Admin only |

The Admin column always has every permission, so no change can leave the
system without an effective Admin.

`GET` response:

```json
{
  "roles": ["admin", "manager", "member", "viewer"],
  "permissions": [
    {
      "permission": "users:read",
      "roles": {
        "admin":   { "granted": true,  "editable": false, "lock_reason": "admin_full_access" },
        "manager": { "granted": false, "editable": true,  "lock_reason": null },
        "member":  { "granted": false, "editable": true,  "lock_reason": null },
        "viewer":  { "granted": false, "editable": true,  "lock_reason": null }
      }
    }
  ],
  "version": "3f9c2a1b7d4e5f60",
  "updated_at": null,
  "updated_by": null
}
```

`lock_reason` is one of `admin_full_access`, `admin_only`,
`audit_admin_only`, `viewer_read_only`, `member_submit_required`, `fixed`.
`updated_at` / `updated_by` describe the most recent change (`null` while the
defaults are untouched).

`PUT` body — the complete list of matrix permissions for **every** editable
role (fixed cells included, exactly as they are), plus the `version` from
`GET`:

```json
{
  "version": "3f9c2a1b7d4e5f60",
  "grants": {
    "manager": ["access_requests:submit", "access_requests:review", "users:read"],
    "member": ["access_requests:submit"],
    "viewer": []
  }
}
```

Responses:

- `200` with the new matrix. Changes apply to every session on its next
  request.
- `422` for an incomplete or invalid update: a missing role, `admin` in
  `grants`, an unknown role or permission, an activity permission, or any
  change to a fixed cell (for example granting `audit:read` to `viewer`). The
  message names the first problem. Nothing is changed.
- `409` when `version` is out of date (someone else saved first). Nothing is
  changed; reload and try again.

All cells and their audit events are written in one transaction. Each role
whose permissions changed gets one `role.permissions_changed` event; saving an
unchanged matrix records nothing.

## Public demo session

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/demo/session` | `{access_token, token_type}` for the `adminDemoUser` demo admin |

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
- New, additive: `GET /audit-events` and the `audit_events` table.
- New, additive: `GET`/`PUT /settings`, `GET /organisation`, the
  `organisation_settings` table and the Admin-only `settings:manage`
  permission. `POST /access-requests` can now also return `403` (requests
  turned off) and `400` (role not requestable); with the default settings it
  behaves exactly as before.
- `activity:read_team` and `activity:read_all` (which guarded nothing) are
  replaced by `activity:read`, which guards the new `GET /activity`.
  `GET /profile` lists `activity:read` for Admin, Manager and Viewer / Auditor
  by default.
- Permissions are now resolved from a stored policy. `GET /profile` no longer
  lists `audit:read` for Viewer / Auditor (it never granted access: the audit
  log has always required Admin) and lists the new `roles:manage` for Admins.
- New, additive: `GET`/`PUT /role-permissions` and the
  `role_permission_grants` table.
- New, additive: the `/access-requests` endpoints and the `access_requests`
  table. An approval also records `user.role_changed` with
  `reason: access_request` and the `request_id`.
