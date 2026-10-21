from sqlalchemy import inspect, text


# =========================================
# EN: Additive, idempotent schema migrations
# JP: 追加のみ・冪等なスキーマ移行
# KR: 추가 전용, 멱등 스키마 마이그레이션
# =========================================
#
# The project has no migration framework; tables are created with
# Base.metadata.create_all, which never alters existing tables. These
# statements bring an existing users table up to date. They only ADD columns
# with safe defaults, never drop or rewrite data, and are safe to run on every
# start-up. Role values are not rewritten; they are normalised when read.

USER_COLUMNS = {
    "is_active": "BOOLEAN NOT NULL DEFAULT TRUE",
    "is_seed": "BOOLEAN NOT NULL DEFAULT FALSE",
    "must_change_password": "BOOLEAN NOT NULL DEFAULT FALSE",
}


def run_migrations(engine) -> list:
    """Add missing user columns. Returns the names of columns added."""
    inspector = inspect(engine)

    if not inspector.has_table("users"):
        return []

    existing = {column["name"] for column in inspector.get_columns("users")}
    added = []

    with engine.begin() as connection:
        for name, definition in USER_COLUMNS.items():
            if name not in existing:
                connection.execute(
                    text(f"ALTER TABLE users ADD COLUMN {name} {definition}")
                )
                added.append(name)

    return added


# =========================================
# EN: Append-only audit log (PostgreSQL)
# JP: 監査ログを追記専用にする（PostgreSQL）
# KR: 감사 로그 추가 전용 (PostgreSQL)
# =========================================
#
# The application never edits or deletes audit events. This trigger makes the
# database refuse it too (UPDATE, DELETE and TRUNCATE), so a bug or a stray
# query can't rewrite history. Creating it is idempotent and touches no data.
# Intentional retention/cleanup in future would need a reviewed migration
# that drops or adjusts this trigger first.

AUDIT_APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION audit_events_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql
"""

AUDIT_TRIGGERS = {
    "audit_events_no_update_delete": (
        "BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE PROCEDURE audit_events_append_only()"
    ),
    "audit_events_no_truncate": (
        "BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE PROCEDURE audit_events_append_only()"
    ),
}


def ensure_audit_log_append_only(engine) -> list:
    """Create the append-only triggers if missing. Returns the names created."""

    if engine.dialect.name != "postgresql" or not inspect(engine).has_table("audit_events"):
        return []

    created = []

    with engine.begin() as connection:
        connection.execute(text(AUDIT_APPEND_ONLY_FUNCTION))

        for name, definition in AUDIT_TRIGGERS.items():
            exists = connection.execute(
                text(
                    "SELECT 1 FROM pg_trigger WHERE tgname = :name "
                    "AND tgrelid = 'audit_events'::regclass"
                ),
                {"name": name},
            ).first()

            if not exists:
                connection.execute(text(f"CREATE TRIGGER {name} {definition}"))
                created.append(name)

    return created


# =========================================
# EN: Role permission defaults
# JP: ロール権限の既定値
# KR: 역할 권한 기본값
# =========================================
#
# Adds a row for each configurable cell that doesn't have one yet, using the
# default policy (which matches the access people had before permissions
# became configurable). Existing rows are never changed, so an Admin's
# choices survive restarts. No other table is touched.

def ensure_role_permission_defaults(engine) -> list:
    """Insert missing configurable cells. Returns the cells added."""
    from app.policy import configurable_cells, default_granted

    if not inspect(engine).has_table("role_permission_grants"):
        return []

    added = []
    with engine.begin() as connection:
        for role, permission in configurable_cells():
            result = connection.execute(
                text(
                    "INSERT INTO role_permission_grants (role, permission, granted)"
                    " VALUES (:role, :permission, :granted)"
                    " ON CONFLICT (role, permission) DO NOTHING"
                ),
                {
                    "role": role.value,
                    "permission": permission.value,
                    "granted": default_granted(role, permission),
                },
            )
            if result.rowcount:
                added.append(f"{role.value}:{permission.value}")
    return added


# =========================================
# EN: Organisation settings defaults
# JP: 組織設定の既定値
# KR: 조직 설정 기본값
# =========================================
#
# Creates the single settings row with the defaults (which match how the app
# behaved before settings existed) if it doesn't exist. An existing row — an
# Admin's saved settings — is never changed.

def ensure_settings_row(engine) -> bool:
    """Insert the default settings row if missing. Returns True if added."""
    from app.settings import DEFAULTS, SETTINGS_ID, join_roles

    if not inspect(engine).has_table("organisation_settings"):
        return False

    with engine.begin() as connection:
        result = connection.execute(
            text(
                "INSERT INTO organisation_settings"
                " (id, access_requests_enabled, requestable_roles, session_minutes, revision)"
                " VALUES (:id, :enabled, :roles, :minutes, 0)"
                " ON CONFLICT (id) DO NOTHING"
            ),
            {
                "id": SETTINGS_ID,
                "enabled": DEFAULTS.access_requests_enabled,
                "roles": join_roles(DEFAULTS.requestable_roles),
                "minutes": DEFAULTS.session_minutes,
            },
        )
    return bool(result.rowcount)
