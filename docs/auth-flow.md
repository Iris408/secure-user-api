# Auth Flow

This document explains authentication and authorization in Secure User
Management API. Endpoint details are in the [API Reference](./api-reference.md).

## Authentication Type

JWT access tokens (HS256, 30 minutes), with bcrypt password hashing.

## Basic Flow

```text
1. An admin creates the account; the server returns a one-time temporary password.
2. The admin shares it with the new user out of band.
3. The user signs in (POST /login) and receives a JWT.
4. Because the password is temporary, only GET /profile and
   POST /profile/password are allowed until the user sets their own password.
5. Every request re-reads the user from the database: role, active status
   and existence are checked each time.
6. Routes require a specific permission (e.g. users:manage), derived from the
   user's role in app/permissions.py.
```

## Password Handling

- Passwords are hashed with bcrypt; plain text is never stored or logged.
- New passwords must be 12–72 bytes (bcrypt reads at most 72 bytes).
- Temporary passwords are 24 random URL-safe characters from Python's
  `secrets` module, returned once with `Cache-Control: no-store`.

## Roles

| Role | Can |
| --- | --- |
| Admin | Manage users and roles; everything the other roles can do |
| Manager | Handle access requests; view their team's activity |
| Member | Use the service; submit access requests |
| Viewer / Auditor | Read activity and audit records; never change data |

Existing `admin` / `Admin` accounts keep admin access and existing `user`
accounts become Members, which have the same access standard accounts had
before. Stored values aren't rewritten.

## Account Lifecycle

- **Deactivate** is the normal way to remove access. It is reversible; the
  user's current session ends immediately and sign-in is refused.
- **Delete** is permanent and only allowed after deactivation.
- Admins cannot change their own role or deactivate/delete themselves, and
  the last active admin who can sign in cannot be demoted or deactivated.

## Demo Seed Accounts

`scripts/seed_demo_users.py` creates 124 synthetic `demo.*` accounts for
demos and tests. They are marked `is_seed`, cannot sign in, and the script
refuses to run outside development, test or demo environments. See the
[Setup Guide](./setup.md#demo-seed-data).

## Future Auth Improvements

- Refresh tokens
- Admin-initiated password reset
- Email verification / invitation links
- Access request, activity and audit endpoints for the reserved permissions
