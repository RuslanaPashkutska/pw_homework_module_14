import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from jose import jwt
from datetime import datetime, timedelta, timezone
import uuid
import asyncio
from src.auth.auth import (
    create_email_verification_token_and_save,
    create_password_reset_token_and_save
)
from src.repository import users as repository_users
from src.database.db import get_db
from src.main import app
from src.conf.config import settings
from unittest.mock import patch

@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_register_user_success(mock_send, test_client):
    email = f"{uuid.uuid4()}@example.com"
    response = await test_client.post("/auth/register", json={
        "email": email,
        "password": "securepassword"
    })

    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == email
    assert data["detail"] == "User successfully registered. Check your email for verification."

    assert "id" in data["user"]
    assert "is_verified" in data["user"]
    assert data["user"]["is_verified"] is False
    assert "created_at" in data["user"]

@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_login_success(mock_send, test_client: AsyncClient, session: AsyncSession):
    email_to_test = f"{uuid.uuid4()}@example.com"
    password = "123456"

    register_response = await test_client.post("/auth/register", json={
        "email": email_to_test,
        "password": password
    })
    assert register_response.status_code == 201

    verification_token = await create_email_verification_token_and_save(email_to_test, session)
    verify_response = await test_client.get(f"/auth/verify_email/{verification_token}")
    assert verify_response.status_code == 200  # El endpoint /verify_email devuelve 200 OK
    assert verify_response.json()["message"] == "Email successfully verified"

    login_response = await test_client.post("/auth/login", json={
        "email": email_to_test,
        "password": password
    })

    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_request_password_reset(mock_send, test_client: AsyncClient, session: AsyncSession):
    email_to_test = f"{uuid.uuid4()}@example.com"


    await test_client.post("/auth/register", json={
        "email": email_to_test,
        "password": "reset1234"
    })

    response = await test_client.post("/auth/request_password_reset", json={
        "email": email_to_test,
    })

    assert response.status_code == 200
    assert "message" in response.json()
    assert response.json()["message"] == "If a user with that email exists, a password reset link has been sent."

@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_verify_email_success(mock_send, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "somepassword"

    register_response = await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })
    assert register_response.status_code == 201

    mock_send.assert_called_once()
    sent_token = mock_send.call_args[0][2]

    verify_response = await test_client.get(f"/auth/verify_email/{sent_token}")

    # assert verify_response.status_code == 200
    print(f"Verify Email Response Status: {verify_response.status_code}")
    print(f"Verify Email Response Body: {verify_response.json()}")
    assert verify_response.status_code == 200
    assert verify_response.json()["message"] == "Email successfully verified"


@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_reset_password_confirm(mock_send, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "resetpass"


    await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })


    token = await create_password_reset_token_and_save(email, session)


    response = await test_client.post("/auth/reset_password", json={
        "token": token,
        "new_password": "newstrongpass"
    })

    assert response.status_code == 200
    assert response.json()["message"] == "Password has been reset successfully"

    verification_token = await create_email_verification_token_and_save(email, session)
    await test_client.get(f"/auth/verify_email/{verification_token}")

    login_response = await test_client.post("/auth/login", json={
        "email": email,
        "password": "newstrongpass"
    })
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_reset_password_form(mock_send, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "formpass"
    await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })

    token = await create_password_reset_token_and_save(email, session)

    response = await test_client.post("/auth/reset-password", data={  # Usar 'data' para Form
        "token": token,
        "new_password": "formnewpass"
    })

    assert response.status_code == 200
    assert response.json()["message"] == "Password has been reset successfully"

    verification_token = await create_email_verification_token_and_save(email, session)
    await test_client.get(f"/auth/verify_email/{verification_token}")

    login_response = await test_client.post("/auth/login", json={
        "email": email,
        "password": "formnewpass"
    })
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()