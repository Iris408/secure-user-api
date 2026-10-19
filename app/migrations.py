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
