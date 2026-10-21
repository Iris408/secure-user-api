# Auth Flow

This document explains authentication, sessions and authorization in Secure
User API. See the [API Reference](./api-reference.md) for endpoint details.

## Authentication

The API issues signed JWT access tokens using HS256. Passwords are hashed
with bcrypt and are never stored in plain text.

The default token lifetime is 30 minutes. Admins can change the configured
session length from 15 to 720 minutes in Settings. The change applies to new
tokens; existing tokens keep the expiry they were issued with.

Clients send a token on protected requests:

```text
Authorization: Bearer <access_token>
```

The API reloads the user from the database on each authenticated request.
This checks that the account still exists and is active, and uses the current
role and permission policy. Deactivation, deletion, role changes and policy
changes therefore take effect on the user’s next request.

## Standard sign-in flow

```text
1. An Admin creates an account.
2. The API returns a generated temporary password once.
3. The Admin shares that password with the user through a secure channel.
4. The user signs in through POST /login and receives a token.
5. The user can access GET /profile and POST /profile/password only.
6. After changing the temporary password, the user can access other
   endpoints allowed by their role and current permissions.
```

`POST /login` accepts a username and password. Unknown usernames and incorrect
passwords receive the same `401` response. Deactivated accounts cannot sign
in.

`POST /token` accepts the OAuth2 form used by Swagger UI’s **Authorize**
button. It issues a token with the same account and session rules as
`POST /login`.

## Password handling

- Passwords are stored as bcrypt hashes; plain-text passwords are not stored.
- New passwords must be 12–72 bytes.
- Generated temporary passwords are random, 24-character URL-safe strings.
- A generated password is returned once with `Cache-Control: no-store`.
- Users with a temporary password must change it before using other API
  routes.
- A user can change their own password with `POST /profile/password`.
- Password reset by an Admin, email verification and invitation links are
  not implemented.

## Roles and permissions

The API supports four roles:

| Role | Default access |
| --- | --- |
| Admin | All permissions, including user management, role configuration, Settings and the Audit Log |
| Manager | Submit and review access requests, and read organisation Activity |
| Member | Submit access requests |
| Viewer / Auditor | Read organisation Activity |

Admins can configure selected permissions for Manager, Member and
Viewer / Auditor. Protected rules keep all permissions for Admin and reserve
user management, role configuration, Settings and the Audit Log for Admins.
The API enforces the saved policy on every request.

`GET /profile` returns the user’s current role and permissions. The frontend
uses this information to adapt navigation and controls, but the API is the
authority for access decisions.

Some rules are role-based and cannot be changed in the permission matrix:

- Only Admins can approve or decline requests for Manager access.
- Users cannot decide their own access requests.
- Admins cannot submit access requests.
- The Audit Log and role-permission endpoints also verify the Admin role.

See the [API Reference](./api-reference.md#roles-and-permissions) for the
full permission matrix and safeguards.

## Account lifecycle

- **Deactivate** is the normal way to remove access. It is reversible.
  Deactivated users cannot sign in, and their next authenticated request is
  rejected.
- **Reactivate** restores access to a deactivated account.
- **Delete** permanently removes an account and is allowed only after
  deactivation.
- Admins cannot change their own role, deactivate themselves or delete
  themselves.
- The last active Admin cannot be demoted or deactivated.

## Demo sessions and seed accounts

The public demo runs as a separate API deployment connected to a dedicated
demo database. It must use `APP_ENV=demo`.

`POST /demo/session` starts a credential-free session as `adminDemoUser`.
The endpoint is available only in demo mode and refuses to start if the
database contains a non-seed account. The resulting token is subject to the
same database-backed role and permission checks as other tokens.

The deterministic seed creates synthetic `demo.*` users and `adminDemoUser`.
Seed accounts are marked `is_seed` and cannot sign in with a password.
Render seeding requires explicit opt-ins and verification of the expected
database name. See the [Setup Guide](./setup.md#seeding-the-demo-database-on-render).

The demo is shared: changes to users, permissions and Settings can affect
other demo visitors. A reset procedure is planned maintenance and is not yet
implemented. See the [API Reference](./api-reference.md#maintenance-restoring-the-public-demo).

## Audit events

The API records successful and failed sign-ins, password changes, user and
permission changes, access request decisions, settings changes and denied
actions. Credentials, tokens, access request reasons and decision notes are
not included in audit details.

Audit records are append-only. The Admin-only Audit Log provides internal
event detail; the Activity endpoint returns a smaller display-safe view to
roles with `activity:read`.

## Related endpoints

| Endpoint | Purpose |
| --- | --- |
| `POST /login` | Sign in with username and password |
| `POST /token` | OAuth2 form sign-in for Swagger UI |
| `POST /demo/session` | Start the demo Admin session; demo deployment only |
| `GET /profile` | Read the current user and permissions |
| `POST /profile/password` | Change the current user’s password |