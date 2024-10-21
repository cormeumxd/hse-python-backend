import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from unittest.mock import Mock
from pydantic import SecretStr

from lecture_4.demo_service.core.users import UserService, UserInfo, UserRole, password_is_longer_than_8
from lecture_4.demo_service.api.main import create_app

app = create_app()

@pytest.fixture
def client():
    user_service = UserService(password_validators=[password_is_longer_than_8])
    user_service.register(
        UserInfo(
            username="admin",
            name="admin",
            birthdate=datetime.fromtimestamp(0.0),
            role=UserRole.ADMIN,
            password="superSecretAdminPassword123",
        )
    )
    app.state.user_service = user_service
    return TestClient(app)

@pytest.fixture
def user_service():
    return UserService(password_validators=[password_is_longer_than_8])

@pytest.fixture
def user_creds(client):
    response = client.post(
        "/user-register",
        json={
            "username": "testuser",
            "name": "Test User",
            "birthdate": "2000-01-01T00:00:00",
            "password": "testpassword123",
        },
    )
    return response.json()

@pytest.fixture
def admin_creds():
    return {
        "username": "admin",
        "password": "superSecretAdminPassword123"
    }

@pytest.mark.parametrize("user_info, expected_status_code", [
    (
        {
            "username": "testuser",
            "name": "Test User",
            "birthdate": "2000-01-01T00:00:00",
            "password": "testpassword123",
        },
        200, 
    ),
    (
        {
            "username": "",
            "name": "",
            "birthdate": "",
            "password": "",
        },
        422,
    ),
])
def test_register_user(client, user_info, expected_status_code):
    response = client.post("/user-register", json=user_info)
    assert response.status_code == expected_status_code

@pytest.mark.parametrize(
    "username, password, expected_status",
    [
        ("testuser", "testpassword123", 200),
        ("nonexistent", "testpassword123", 401),
        ("testuser", "wrongpassword", 401),
        (None, None, 400)
    ],
)
def test_get_user_api(client, username, password, expected_status, user_creds):
    response = client.post(
        "/user-get",
        params={"username": username},
        auth=(username, password),
    )
    assert response.status_code == expected_status

@pytest.mark.parametrize("password,expected", [
    ("validPassword123", True),
    ("short", False)
])
def test_password_is_longer_than_8(password, expected):
    assert password_is_longer_than_8(password) == expected

@pytest.mark.parametrize("id,expected", [
    (1, 200),
    (1337, 404)
])
def test_get(client, user_creds, admin_creds, id, expected):
    response = client.post("/user-get", auth=(admin_creds["username"], admin_creds["password"]),
                               params={"id": id})
    assert response.status_code == expected

def test_get_error_both(client, user_creds, admin_creds):
    response = client.post("/user-get", auth=(admin_creds["username"], admin_creds["password"]),
                               params={"id": 1, "username": "testuser"})
    assert response.status_code == 400


@pytest.mark.parametrize("id,expected", [
    (1, 200),
    (1337, 400)
])
def test_promote(client, admin_creds, id, expected):
    response = client.post("/user-promote", auth=(admin_creds["username"], admin_creds["password"]),
                               params={"id": id})
    assert response.status_code == expected

def test_promote_not_admin(client, admin_creds):
    response = client.post("/user-promote", auth=('123', '123'),
                               params={"id": 1})
    assert response.status_code == 401


def test_user_register_username_taken(user_service):
    user_info = UserInfo(username="test_user", name="Test User", birthdate=datetime.now(),
                         role=UserRole.USER, password="testpassword123")
    user_service.register(user_info)
    with pytest.raises(ValueError, match="username is already taken"):
        user_service.register(user_info)

def test_grant_admin_user_not_found(user_service):
    with pytest.raises(ValueError, match="user not found"):
        user_service.grant_admin(9999)


def test_user_register_short_password(user_service):
    user_info = UserInfo(username="test_user_2", name="Test User", birthdate=datetime.now(),
                         role=UserRole.USER, password="short")
    with pytest.raises(ValueError, match="invalid password"):
        user_service.register(user_info)
