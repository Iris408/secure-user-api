import pytest

from app.auth import INSECURE_DEFAULT_KEY, InsecureConfiguration, load_secret_key


@pytest.mark.parametrize(
    "environ",
    [
        {},  # APP_ENV unset is treated as production
        {"APP_ENV": "production"},
        {"APP_ENV": "demo"},
        {"APP_ENV": "production", "SECRET_KEY": ""},
        {"APP_ENV": "production", "SECRET_KEY": "   "},
        {"APP_ENV": "production", "SECRET_KEY": INSECURE_DEFAULT_KEY},
        {"SECRET_KEY": INSECURE_DEFAULT_KEY},
    ],
)
def test_deployed_environments_refuse_to_start_without_a_private_key(environ):
    with pytest.raises(InsecureConfiguration):
        load_secret_key(environ)


def test_deployed_environments_use_the_configured_key():
    assert load_secret_key({"APP_ENV": "production", "SECRET_KEY": "s3cr3t-value"}) == "s3cr3t-value"
    assert load_secret_key({"SECRET_KEY": "s3cr3t-value"}) == "s3cr3t-value"


@pytest.mark.parametrize("app_env", ["development", "test", "Development"])
def test_local_environments_may_fall_back(app_env):
    assert load_secret_key({"APP_ENV": app_env}) == INSECURE_DEFAULT_KEY
    assert load_secret_key({"APP_ENV": app_env, "SECRET_KEY": "custom"}) == "custom"
