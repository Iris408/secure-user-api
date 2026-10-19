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
