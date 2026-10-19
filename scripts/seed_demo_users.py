"""
Create or remove the 124 synthetic demo users and the adminDemoUser account.

    APP_ENV=development python -m scripts.seed_demo_users
    APP_ENV=development python -m scripts.seed_demo_users --remove

Refuses to run outside development / test / demo environments, and refuses
Render targets by default. The dedicated demo database on Render can only be
seeded with every opt-in present:

    APP_ENV=demo DATABASE_URL=... python -m scripts.seed_demo_users \\
        --allow-render-demo --expected-database <demo database name>

See app/demo_seed.py for the full list of safeguards.
"""

import argparse
import sys

from app.database import Base, SessionLocal, engine
from app.demo_seed import (
    SEED_COUNT,
    SeedNotAllowed,
    assert_seed_allowed,
    ensure_demo_admin,
    is_render_target,
    remove_demo_users,
    seed_demo_users,
    verify_demo_database,
)
from app.migrations import run_migrations


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--remove",
        action="store_true",
        help="delete all demo (is_seed) users instead of creating them",
    )
    parser.add_argument("--count", type=int, default=SEED_COUNT)
    parser.add_argument(
        "--allow-render-demo",
        action="store_true",
        help="opt in to seeding the dedicated AccessHub demo database on Render "
        "(also requires APP_ENV=demo and --expected-database)",
    )
    parser.add_argument(
        "--expected-database",
        help="name of the database you intend to seed; must equal "
        "current_database() and contain no non-seed users",
    )
    args = parser.parse_args(argv)

    try:
        assert_seed_allowed(allow_render_demo=args.allow_render_demo)

        # Verify the target before creating tables or writing anything.
        if is_render_target() or args.expected_database:
            with SessionLocal() as db:
                verify_demo_database(db, args.expected_database)
    except SeedNotAllowed as error:
        print(f"Refusing to run: {error}", file=sys.stderr)
        return 2

    Base.metadata.create_all(bind=engine)
    run_migrations(engine)

    options = {"allow_render_demo": args.allow_render_demo}

    with SessionLocal() as db:
        try:
            if args.remove:
                removed = remove_demo_users(db, **options)
                print(f"Removed {removed} demo users.")
            else:
                created = seed_demo_users(db, count=args.count, **options)
                demo_admin = ensure_demo_admin(db, **options)
                print(
                    f"Created {created} demo users (is_seed=true)"
                    f"{' and adminDemoUser' if demo_admin else ''}. "
                    "Demo accounts cannot sign in with a password."
                )
        except SeedNotAllowed as error:
            print(f"Refusing to run: {error}", file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
