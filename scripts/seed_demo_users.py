"""
Create or remove the 124 synthetic demo users.

    APP_ENV=development python -m scripts.seed_demo_users
    APP_ENV=development python -m scripts.seed_demo_users --remove

Refuses to run outside development / test / demo environments. See
app/demo_seed.py for the full list of safeguards.
"""

import argparse
import sys

from app.database import Base, SessionLocal, engine
from app.demo_seed import (
    SEED_COUNT,
    SeedNotAllowed,
    assert_seed_allowed,
    ensure_demo_guide,
    remove_demo_users,
    seed_demo_users,
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
    args = parser.parse_args(argv)

    try:
        assert_seed_allowed()
    except SeedNotAllowed as error:
        print(f"Refusing to run: {error}", file=sys.stderr)
        return 2

    Base.metadata.create_all(bind=engine)
    run_migrations(engine)

    with SessionLocal() as db:
        if args.remove:
            removed = remove_demo_users(db)
            print(f"Removed {removed} demo users.")
        else:
            created = seed_demo_users(db, count=args.count)
            guide = ensure_demo_guide(db)
            print(
                f"Created {created} demo users (is_seed=true)"
                f"{' and the demo guide account' if guide else ''}. "
                "Demo accounts cannot sign in with a password."
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
