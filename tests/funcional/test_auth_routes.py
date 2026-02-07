import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError
import uuid
from unittest.mock import patch, AsyncMock, ANY
from fastapi import status, HTTPException
from src.database.models import User

from src.auth.auth import (
    create_email_verification_token_and_save,
    create_password_reset_token_and_save,
    get_password_hash
)
from src.repository import users as repository_users


@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_register_user_success(mock_send, test_client: AsyncClient):
    email = f"{uuid.uuid4()}@example.com"
    response = await test_client.post("/auth/register", json={
        "email": email,
        "password": "securepassword"
    })

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["user"]["email"] == email
    assert data["detail"] == "User successfully registered. Check your email for verification."
    assert "id" in data["user"]
    assert "is_verified" in data["user"]
    assert data["user"]["is_verified"] is False
    assert "created_at" in data["user"]

    mock_send.assert_awaited_once_with(email, email, ANY, "verify_email")



@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_register_user_internal_flow(mock_send_email, test_client: AsyncClient, session: AsyncSession):
    """
    Este test cubre internamente las líneas que generan el hash, crean el usuario y guardan el token.
    """
    email = f"{uuid.uuid4()}@example.com"
    password = "flowpassword123"

    response = await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["user"]["email"] == email
    assert data["detail"] == "User successfully registered. Check your email for verification."

    user = await repository_users.get_user_by_email(session, email)
    assert user is not None
    assert user.email == email
    assert user.is_verified is False
    assert user.hashed_password != password

@patch("src.routes.auth.repository_users.get_user_by_email")
@pytest.mark.asyncio
async def test_register_user_already_exists(mock_get_user_by_email, test_client: AsyncClient):
    mock_existing_user = AsyncMock()
    mock_existing_user.email = "existing@example.com"
    mock_get_user_by_email.return_value = mock_existing_user


    response = await test_client.post("/auth/register", json={
        "email": "existing@example.com",
        "password": "password123"
    })

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["detail"] == "User already exists"
    mock_get_user_by_email.assert_awaited_once_with(ANY, "existing@example.com")

@patch("src.routes.auth.send_email")
@patch("src.routes.auth.create_email_verification_token_and_save", return_value="dummy_token")
@pytest.mark.asyncio
async def test_register_user_email_send_failure(
    mock_create_email_token,
    mock_send_email,
    test_client: AsyncClient,
    session: AsyncSession
):
    mock_send_email.side_effect = Exception("Simulated email sending failure")

    email_to_test = f"{uuid.uuid4()}@example.com"
    password = "testpassword"

    response = await test_client.post(
        "/auth/register",
        json={"email": email_to_test, "password": password}
    )

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()

    assert data[
               "detail"] == "User successfully registered, but failed to send verification email. Please contact support."
    assert data["user"]["email"] == email_to_test


    mock_send_email.assert_awaited_once_with(
        email_to_test,
        email_to_test,
        "dummy_token",
        "verify_email"
    )


    db_user = await repository_users.get_user_by_email(session, email_to_test)
    assert db_user is not None
    assert db_user.is_verified is False

@patch("src.routes.auth.create_refresh_token", return_value="fake_refresh_token")
@patch("src.routes.auth.create_access_token", return_value="fake_access_token")
@patch("src.routes.auth.verify_password", return_value=True) # Contraseña correcta
@patch("src.routes.auth.repository_users.get_user_by_email")
@pytest.mark.asyncio
async def test_login_success(
    mock_get_user_by_email, mock_verify_password, mock_create_access_token, mock_create_refresh_token,
    test_client: AsyncClient
):
    mock_user = AsyncMock()
    mock_user.email = "verified@example.com"
    mock_user.hashed_password = get_password_hash("password123")
    mock_user.is_verified = True

    mock_get_user_by_email.return_value = mock_user

    login_response = await test_client.post("/auth/login", data={
        "username": "verified@example.com",
        "password": "password123"
    })

    assert login_response.status_code == status.HTTP_200_OK
    data = login_response.json()
    assert data["access_token"] == "fake_access_token"
    assert data["refresh_token"] == "fake_refresh_token"
    assert data["token_type"] == "bearer"

    mock_get_user_by_email.assert_awaited_once_with(ANY, "verified@example.com")
    mock_verify_password.assert_called_once_with("password123", mock_user.hashed_password)
    mock_create_access_token.assert_called_once_with(data={"sub": "verified@example.com"})
    mock_create_refresh_token.assert_called_once_with(data={"sub": "verified@example.com"})


@pytest.mark.asyncio
@patch("src.routes.auth.repository_users.get_user_by_email")
async def test_login_invalid_credentials_user_not_found(mock_get_user_by_email, test_client: AsyncClient):
    mock_get_user_by_email.return_value = None


    response = await test_client.post("/auth/login", data={"username": "nonexistent@example.com", "password": "wrong"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Invalid credentials"}
    mock_get_user_by_email.assert_awaited_once_with(ANY, "nonexistent@example.com")


@pytest.mark.asyncio
@patch("src.routes.auth.repository_users.get_user_by_email")
@patch("src.routes.auth.verify_password")
async def test_login_invalid_credentials_wrong_password(
    mock_verify_password,
    mock_get_user_by_email,
    test_client: AsyncClient
):
    mock_user = AsyncMock()
    mock_user.email = "test@example.com"
    mock_user.hashed_password = get_password_hash("correct_password")
    mock_user.is_verified = True

    mock_get_user_by_email.return_value = mock_user
    mock_verify_password.return_value = False


    response = await test_client.post("/auth/login", data={"username": "test@example.com", "password": "wrong_password"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Invalid credentials"}
    mock_get_user_by_email.assert_awaited_once_with(ANY, "test@example.com")
    mock_verify_password.assert_called_once_with("wrong_password", mock_user.hashed_password)


@pytest.mark.asyncio
@patch("src.routes.auth.repository_users.get_user_by_email")
@patch("src.routes.auth.verify_password")
async def test_login_email_not_verified(
    mock_verify_password,
    mock_get_user_by_email,
    test_client: AsyncClient
):
    mock_user = AsyncMock()
    mock_user.email = "unverified@example.com"
    mock_user.hashed_password = get_password_hash("password123")
    mock_user.is_verified = False

    mock_get_user_by_email.return_value = mock_user
    mock_verify_password.return_value = True


    response = await test_client.post("/auth/login", data={"username": "unverified@example.com", "password": "password123"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "Email not verified. Please check your inbox."}
    mock_get_user_by_email.assert_awaited_once_with(ANY, "unverified@example.com")
    mock_verify_password.assert_called_once_with("password123", mock_user.hashed_password)


@patch("src.routes.auth.send_email", return_value=None)
@pytest.mark.asyncio
async def test_verify_email_success(mock_send, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "somepassword"

    register_response = await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })
    assert register_response.status_code == status.HTTP_201_CREATED

    mock_send.assert_called_once()
    sent_token = mock_send.call_args[0][2]

    verify_response = await test_client.get(f"/auth/verify_email/{sent_token}")

    assert verify_response.status_code == status.HTTP_200_OK
    assert verify_response.json()["message"] == "Email successfully verified"

    user_in_db = await repository_users.get_user_by_email(session, email)
    assert user_in_db.is_verified is True


@patch("src.routes.auth.verify_email_token")
@pytest.mark.asyncio
async def test_verify_email_invalid_token(mock_verify_email_token, test_client: AsyncClient):
    mock_verify_email_token.return_value = None

    response = await test_client.get("/auth/verify_email/invalid_token_123")

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid or expired verification token"
    mock_verify_email_token.assert_awaited_once_with("invalid_token_123", ANY)


@patch("src.routes.auth.send_email", return_value=None)
@patch("src.routes.auth.create_password_reset_token_and_save", return_value="dummy_reset_token")
@patch("src.routes.auth.repository_users.get_user_by_email")
@pytest.mark.asyncio
async def test_request_password_reset_success(
    mock_get_user_by_email, mock_create_password_reset_token_and_save, mock_send_email,
    test_client: AsyncClient
):
    mock_user = AsyncMock(email="reset@example.com")
    mock_get_user_by_email.return_value = mock_user

    response = await test_client.post("/auth/request_password_reset", json={
        "email": "reset@example.com",
    })
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "If a user with that email exists, a password reset link has been sent."
    mock_get_user_by_email.assert_awaited_once_with(ANY, "reset@example.com")
    mock_create_password_reset_token_and_save.assert_awaited_once_with("reset@example.com", ANY)
    mock_send_email.assert_awaited_once_with(
        "reset@example.com", "reset@example.com", "dummy_reset_token", "reset_password"
    )

@patch("src.routes.auth.repository_users.get_user_by_email")
@patch("src.routes.auth.create_password_reset_token_and_save")
@patch("src.routes.auth.send_email")
@pytest.mark.asyncio
async def test_request_password_reset_user_not_found(
    mock_send_email, mock_create_token, mock_get_user_by_email, test_client: AsyncClient
):
    mock_get_user_by_email.return_value = None

    response = await test_client.post("/auth/request_password_reset", json={
        "email": "nonexistent@example.com"
    })

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "If a user with that email exists, a password reset link has been sent."
    mock_get_user_by_email.assert_awaited_once_with(ANY, "nonexistent@example.com")
    mock_create_token.assert_not_awaited()
    mock_send_email.assert_not_awaited()


@patch("src.routes.auth.send_email") # Mock 1
@patch("src.routes.auth.create_email_verification_token_and_save", return_value="dummy_verification_token")
@pytest.mark.asyncio
async def test_request_password_reset_email_send_failure(mock_create_email_token_and_save, mock_send_email, test_client: AsyncClient, session: AsyncSession
):
    email_to_test = f"{uuid.uuid4()}@example.com"
    await test_client.post("/auth/register", json={
        "email": email_to_test,
        "password": "reset1234"
    })
    mock_send_email.reset_mock()
    mock_send_email.side_effect = Exception("SMTP server error")

    response = await test_client.post("/auth/request_password_reset", json={
        "email": email_to_test,
    })

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "If a user with that email exists, a password reset link has been sent."
    mock_send_email.assert_awaited_once()


@patch("src.routes.auth.send_email", return_value=None)
@patch("src.routes.auth.create_email_verification_token_and_save", return_value="dummy_verification_token")
@pytest.mark.asyncio
async def test_reset_password_json_success(mock_send, mock_create_email_token, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "resetpass"

    await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })

    token = await create_password_reset_token_and_save(email, db=session)

    response = await test_client.post("/auth/reset_password", json={
        "token": token,
        "new_password": "newstrongpass"
    })

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Password has been reset successfully"

    user_in_db = await repository_users.get_user_by_email(session, email)
    user_in_db.is_verified = True
    session.add(user_in_db)
    await session.commit()
    await session.refresh(user_in_db)

    login_response = await test_client.post("/auth/login", data={
        "username": email,
        "password": "newstrongpass"
    })
    assert login_response.status_code == status.HTTP_200_OK
    assert "access_token" in login_response.json()


@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_json_invalid_or_expired_token(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.return_value = None

    response = await test_client.post("/auth/reset_password", json={
        "token": "invalid_token",
        "new_password": "newpassword123"
    })

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid or expired reset token"
    mock_auth_reset_password_logic.assert_awaited_once_with("invalid_token", "newpassword123", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_json_jwt_error(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = JWTError("Invalid JWT")

    response = await test_client.post("/auth/reset_password", json={
        "token": "corrupted_token",
        "new_password": "newpassword123"
    })

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid or expired token"
    mock_auth_reset_password_logic.assert_awaited_once_with("corrupted_token", "newpassword123", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_json_unexpected_error(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = ValueError("Something went wrong")

    response = await test_client.post("/auth/reset_password", json={
        "token": "valid_token_but_error",
        "new_password": "newpassword123"
    })

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "An unexpected error occurred" in response.json()["detail"]
    mock_auth_reset_password_logic.assert_awaited_once_with("valid_token_but_error", "newpassword123", ANY)


@patch("src.routes.auth.send_email", return_value=None)
@patch("src.routes.auth.create_email_verification_token_and_save", return_value="dummy_verification_token")
@pytest.mark.asyncio
async def test_reset_password_form_success(mock_send, mock_create_email_token, test_client: AsyncClient, session: AsyncSession):
    email = f"{uuid.uuid4()}@example.com"
    password = "formpass"
    await test_client.post("/auth/register", json={
        "email": email,
        "password": password
    })

    token = await create_password_reset_token_and_save(email, db=session)

    response = await test_client.post("/auth/reset-password-form", data={
        "token": token,
        "new_password": "formnewpass"
    })

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["message"] == "Password has been reset successfully"

    user_in_db = await repository_users.get_user_by_email(session, email)
    user_in_db.is_verified = True
    session.add(user_in_db)
    await session.commit()
    await session.refresh(user_in_db)

    login_response = await test_client.post("/auth/login", data={
        "username": email,
        "password": "formnewpass"
    })
    assert login_response.status_code == status.HTTP_200_OK
    assert "access_token" in login_response.json()


@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_form_invalid_or_expired_token(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.return_value = None

    response = await test_client.post("/auth/reset-password-form", data={
        "token": "invalid_form_token",
        "new_password": "newpassword456"
    })

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid or expired reset token"
    mock_auth_reset_password_logic.assert_awaited_once_with("invalid_form_token", "newpassword456", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_form_jwt_error(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = JWTError("Invalid JWT Form")

    response = await test_client.post("/auth/reset-password-form", data={
        "token": "corrupted_form_token",
        "new_password": "newpassword456"
    })

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Invalid or expired token"
    mock_auth_reset_password_logic.assert_awaited_once_with("corrupted_form_token", "newpassword456", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_form_unexpected_error(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = TypeError("Bad type in data")

    response = await test_client.post("/auth/reset-password-form", data={
        "token": "valid_form_token_but_error",
        "new_password": "newpassword456"
    })

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "An unexpected error occurred" in response.json()["detail"]
    mock_auth_reset_password_logic.assert_awaited_once_with("valid_form_token_but_error", "newpassword456", ANY)


@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_json_re_raise_http_exception(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Token already used or malformed during internal logic"
    )

    response = await test_client.post("/auth/reset_password", json={
        "token": "some_token",
        "new_password": "new_pass"
    })

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Token already used or malformed during internal logic"
    mock_auth_reset_password_logic.assert_awaited_once_with("some_token", "new_pass", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_form_re_raise_http_exception(
    mock_auth_reset_password_logic, test_client: AsyncClient
):
    mock_auth_reset_password_logic.side_effect = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden operation from internal service"
    )

    response = await test_client.post("/auth/reset-password-form", data={
        "token": "some_form_token",
        "new_password": "new_form_pass"
    })

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Forbidden operation from internal service"
    mock_auth_reset_password_logic.assert_awaited_once_with("some_form_token", "new_form_pass", ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_json_handles_http_exception_from_logic(
    mock_auth_reset_password_logic,
    test_client: AsyncClient
):
    """
    Prueba el manejo de HTTPException re-lanzada desde auth_reset_password_logic.
    """
    simulated_http_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operation not allowed by internal auth logic"
    )
    mock_auth_reset_password_logic.side_effect = simulated_http_exception

    test_token = "some_valid_looking_token_that_causes_internal_http_error"
    test_new_password = "MyNewSecurePassword!"

    response = await test_client.post("/auth/reset_password", json={
        "token": test_token,
        "new_password": test_new_password
    })

    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json()["detail"] == "Operation not allowed by internal auth logic"

    mock_auth_reset_password_logic.assert_awaited_once_with(test_token, test_new_password, ANY)

@patch("src.routes.auth.auth_reset_password_logic")
@pytest.mark.asyncio
async def test_reset_password_form_handles_http_exception_from_logic(
    mock_auth_reset_password_logic,
    test_client: AsyncClient
):
    """
    Prueba el manejo de HTTPException re-lanzada desde auth_reset_password_logic (para endpoint de formulario).
    """
    simulated_http_exception = HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="User data conflict during password reset"
    )
    mock_auth_reset_password_logic.side_effect = simulated_http_exception

    test_token = "some_form_token_causing_internal_http_error"
    test_new_password = "AnotherNewSecurePassword!"

    response = await test_client.post("/auth/reset-password-form", data={
        "token": test_token,
        "new_password": test_new_password
    })

    assert response.status_code == status.HTTP_409_CONFLICT
    assert response.json()["detail"] == "User data conflict during password reset"

    mock_auth_reset_password_logic.assert_awaited_once_with(test_token, test_new_password, ANY)


@pytest.mark.asyncio
async def test_register_user_email_send_failure_alt_patch(
    test_client: AsyncClient,
    session: AsyncSession
):
    email_to_test = f"fail_{uuid.uuid4()}@example.com"
    password = "testpassword123"

    with patch("src.routes.auth.send_email", side_effect=Exception("Simulated email failure")) as mock_send_email:
        with patch("src.routes.auth.create_email_verification_token_and_save", return_value="some_token") as mock_create_token:

            response = await test_client.post(
                "/auth/register",
                json={"email": email_to_test, "password": password}
            )

            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()


            assert data["detail"] == "User successfully registered, but failed to send verification email. Please contact support."
            assert data["user"]["email"] == email_to_test

            mock_send_email.assert_awaited_once_with(
                email_to_test, email_to_test, "some_token", "verify_email"
            )
            mock_create_token.assert_awaited_once_with(email_to_test, ANY)


            db_user = await session.get(User, data["user"]["id"])
            assert db_user is not None
            assert db_user.is_verified is False
            assert db_user.email == email_to_test

