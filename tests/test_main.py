import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "secure-user-management-api",
    }

def test_openapi_schema_available():
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert "openapi" in response.json()    

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://192.0.0.2:5175",
    "https://jwt-authentication-dashboard-sepia.vercel.app",
    "https://accesshub-7jy6awsnz-iris408.vercel.app",
    "https://accesshub-iris408.vercel.app",
]


@pytest.mark.parametrize("origin", ALLOWED_ORIGINS)
def test_cors_allows_the_accesshub_frontends(client, origin):
    response = client.options(
        "/profile",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == origin


def test_cors_refuses_other_origins(client):
    response = client.options(
        "/profile",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
