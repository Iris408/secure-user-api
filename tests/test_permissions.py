import pytest

from app.permissions import (
    Permission,
    Role,
    normalize_role,
    parse_role,
    permissions_for,
)


def test_role_permission_matrix():
    # The agreed boundaries, spelled out so any change is deliberate.
    assert permissions_for("admin") == sorted(p.value for p in Permission)
    assert permissions_for("manager") == [
        "access_requests:review",
        "access_requests:submit",
        "activity:read_team",
    ]
    assert permissions_for("member") == ["access_requests:submit"]
    assert permissions_for("viewer") == ["activity:read_all", "audit:read"]


def test_only_admin_can_manage_or_read_users():
    for role in Role:
        allowed = role is Role.ADMIN
        assert ("users:manage" in permissions_for(role)) is allowed
        assert ("users:read" in permissions_for(role)) is allowed


def test_viewer_has_no_write_permissions():
    write_permissions = {
        Permission.USERS_MANAGE.value,
        Permission.ACCESS_REQUESTS_SUBMIT.value,
        Permission.ACCESS_REQUESTS_REVIEW.value,
    }
    assert write_permissions.isdisjoint(permissions_for("viewer"))


@pytest.mark.parametrize(
    "stored, expected",
    [
        ("admin", Role.ADMIN),
        ("Admin", Role.ADMIN),
        (" ADMIN ", Role.ADMIN),
        ("user", Role.MEMBER),
        ("manager", Role.MANAGER),
        ("Viewer", Role.VIEWER),
        ("auditor", Role.VIEWER),
        ("something-else", Role.MEMBER),
        (None, Role.MEMBER),
        ("", Role.MEMBER),
    ],
)
def test_existing_role_values_map_to_four_roles(stored, expected):
    assert normalize_role(stored) is expected


def test_parse_role_accepts_legacy_alias_and_rejects_unknown_roles():
    assert parse_role("user") is Role.MEMBER
    assert parse_role("Manager") is Role.MANAGER

    with pytest.raises(ValueError):
        parse_role("superuser")
