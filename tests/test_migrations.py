from sqlalchemy import inspect, text

from app.database import engine
from app.migrations import USER_COLUMNS, run_migrations


def create_legacy_users_table():
    # The schema as deployed before this phase.
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS users"))
        connection.execute(text(
            "CREATE TABLE users ("
            " id SERIAL PRIMARY KEY,"
            " username VARCHAR UNIQUE,"
            " hashed_password VARCHAR,"
            " role VARCHAR)"
        ))
        connection.execute(text(
            "INSERT INTO users (username, hashed_password, role) VALUES"
            " ('adminuser', 'x', 'admin'),"
            " ('testuser', 'x', 'Admin'),"
            " ('standard', 'x', 'user')"
        ))


def test_migration_adds_columns_without_touching_existing_rows():
    create_legacy_users_table()

    added = run_migrations(engine)

    assert sorted(added) == sorted(USER_COLUMNS)
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    assert set(USER_COLUMNS) <= columns

    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT username, role, is_active, is_seed, must_change_password"
            " FROM users ORDER BY id"
        )).all()

    # Role values are left as stored and every account stays active.
    assert [tuple(row) for row in rows] == [
        ("adminuser", "admin", True, False, False),
        ("testuser", "Admin", True, False, False),
        ("standard", "user", True, False, False),
    ]


def test_migration_is_idempotent():
    create_legacy_users_table()
    run_migrations(engine)

    assert run_migrations(engine) == []


def test_startup_adds_the_audit_log_to_an_existing_database():
    from app.database import Base
    from app.migrations import ensure_audit_log_append_only

    create_legacy_users_table()
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS audit_events"))

    # The same steps app.main runs at start-up.
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    created = ensure_audit_log_append_only(engine)

    assert inspect(engine).has_table("audit_events")
    assert sorted(created) == ["audit_events_no_truncate", "audit_events_no_update_delete"]
    assert ensure_audit_log_append_only(engine) == []

    with engine.connect() as connection:
        users = connection.execute(text("SELECT username, role FROM users ORDER BY id")).all()
        audit_rows = connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one()

    # Existing accounts are untouched and no audit history is invented.
    assert [tuple(row) for row in users] == [
        ("adminuser", "admin"), ("testuser", "Admin"), ("standard", "user"),
    ]
    assert audit_rows == 0


def test_startup_adds_access_requests_to_an_existing_database():
    from app.database import Base

    create_legacy_users_table()
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS access_requests"))

    # The same steps app.main runs at start-up.
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)

    assert inspect(engine).has_table("access_requests")
    indexes = {index["name"]: index for index in inspect(engine).get_indexes("access_requests")}
    assert indexes["uq_access_requests_one_pending_per_user"]["unique"]

    with engine.connect() as connection:
        requests = connection.execute(text("SELECT COUNT(*) FROM access_requests")).scalar_one()
        users = connection.execute(text("SELECT username, role FROM users ORDER BY id")).all()

    # No request history is invented and existing roles are untouched.
    assert requests == 0
    assert [tuple(row) for row in users] == [
        ("adminuser", "admin"), ("testuser", "Admin"), ("standard", "user"),
    ]


def test_startup_adds_role_permission_defaults_to_an_existing_database():
    from app.database import Base
    from app.migrations import ensure_role_permission_defaults

    create_legacy_users_table()
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS role_permission_grants"))

    # The same steps app.main runs at start-up.
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    added = ensure_role_permission_defaults(engine)

    assert len(added) == 9
    assert ensure_role_permission_defaults(engine) == []

    with engine.connect() as connection:
        granted = connection.execute(text(
            "SELECT role || ':' || permission FROM role_permission_grants"
            " WHERE granted ORDER BY 1"
        )).scalars().all()
        users = connection.execute(text("SELECT username, role FROM users ORDER BY id")).all()

    # Only today's grants are stored as granted; users are untouched.
    assert granted == [
        "manager:access_requests:review",
        "manager:access_requests:submit",
        "manager:activity:read",
        "viewer:activity:read",
    ]
    assert [tuple(row) for row in users] == [
        ("adminuser", "admin"), ("testuser", "Admin"), ("standard", "user"),
    ]


def test_startup_adds_default_settings_to_an_existing_database():
    from app.database import Base
    from app.migrations import ensure_settings_row

    create_legacy_users_table()
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE IF EXISTS organisation_settings"))

    # The same steps app.main runs at start-up.
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)

    assert ensure_settings_row(engine) is True
    assert ensure_settings_row(engine) is False

    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT id, organisation_name, timezone, access_requests_enabled,"
            " requestable_roles, session_minutes, revision FROM organisation_settings"
        )).all()
        users = connection.execute(text("SELECT username, role FROM users ORDER BY id")).all()

    # Defaults match how the app behaved before settings; users are untouched.
    assert [tuple(row) for row in rows] == [(1, None, None, True, "manager,member,viewer", 30, 0)]
    assert [tuple(row) for row in users] == [
        ("adminuser", "admin"), ("testuser", "Admin"), ("standard", "user"),
    ]
