import pytest
from httpx import AsyncClient
from unittest.mock import patch, AsyncMock, MagicMock
from datetime import date, timedelta
import uuid
from fastapi import status

from sqlalchemy.ext.asyncio import AsyncSession
from src.repository import users as repository_users
from src.auth.auth import create_access_token, ALGORITHM, create_email_verification_token_and_save
from jose import jwt
from src.database.models import User



@pytest.fixture
async def authenticated_user_token(test_client: AsyncClient, session: AsyncSession):
    test_email = f"auth_user_{uuid.uuid4()}@example.com"
    test_password = "secure_test_password_123"


    register_response = await test_client.post("/auth/register", json={
        "email": test_email,
        "password": test_password
    })
    assert register_response.status_code == status.HTTP_201_CREATED

    user_in_db = await repository_users.get_user_by_email(session, test_email)
    assert user_in_db is not None

    user_in_db.is_verified = True

    user_in_db.email_verification_token = "mocked_verification_token_for_fixture"
    await session.commit()


    token_data = {"sub": user_in_db.email, "scope": ["access_token"], "user_id": user_in_db.id}
    access_token = create_access_token(data=token_data)

    return {"Authorization": f"Bearer {access_token}"}



@patch("src.cache.redis_client.redis_client")
@pytest.mark.asyncio
async def test_create_and_manage_contact(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    contact_data = {
        "first_name": "Alice",
        "last_name": "Smith",
        "email": f"alice_{uuid.uuid4()}@example.com",
        "phone": "1234567890",
        "birthday": str(date.today()),
        "extra_info": "Functional test contact"
    }

    response = await test_client.post("/contacts/", json=contact_data, headers=headers)
    assert response.status_code == status.HTTP_201_CREATED
    created_contact = response.json()
    assert created_contact["first_name"] == contact_data["first_name"]
    assert created_contact["email"] == contact_data["email"]

    contact_id = created_contact["id"]

    response_get = await test_client.get(f"/contacts/{contact_id}", headers=headers)
    assert response_get.status_code == status.HTTP_200_OK
    assert response_get.json()["email"] == contact_data["email"]


@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_update_contact_success(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    contact_data = {
        "first_name": "UpdateTest",
        "last_name": "User",
        "email": f"update_{uuid.uuid4()}@example.com",
        "phone": "123456789",
        "birthday": str(date.today()),
        "extra_info": "Initial"
    }

    response = await test_client.post("/contacts/", json=contact_data, headers=headers)
    assert response.status_code == status.HTTP_201_CREATED
    contact_id = response.json()["id"]

    updated_data = {
        "first_name": "Updated",
        "last_name": "User",
        "email": f"updated_{uuid.uuid4()}@example.com",
        "phone": "987654321",
        "birthday": str(date.today()),
        "extra_info": "Updated info"
    }

    response_put = await test_client.put(f"/contacts/{contact_id}", json=updated_data, headers=headers)
    assert response_put.status_code == status.HTTP_200_OK
    updated_contact = response_put.json()
    assert updated_contact["first_name"] == "Updated"
    assert updated_contact["email"] == updated_data["email"]


@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_delete_contact_success(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    contact_data = {
        "first_name": "DeleteTest",
        "last_name": "User",
        "email": f"delete_{uuid.uuid4()}@example.com",
        "phone": "111111111",
        "birthday": str(date.today()),
        "extra_info": "To be deleted"
    }

    response = await test_client.post("/contacts/", json=contact_data, headers=headers)
    assert response.status_code == status.HTTP_201_CREATED
    contact_id = response.json()["id"]

    response_delete = await test_client.delete(f"/contacts/{contact_id}", headers=headers)
    assert response_delete.status_code == status.HTTP_204_NO_CONTENT

    response_check = await test_client.get(f"/contacts/{contact_id}", headers=headers)
    assert response_check.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_get_all_contacts(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    contact_data_1 = {
        "first_name": "Charlie", "last_name": "Brown",
        "email": f"charlie_{uuid.uuid4()}@example.com",
        "phone": "1111111111", "birthday": str(date.today()), "extra_info": ""
    }
    contact_data_2 = {
        "first_name": "Lucy", "last_name": "Van Pelt",
        "email": f"lucy_{uuid.uuid4()}@example.com",
        "phone": "2222222222", "birthday": str(date.today() - timedelta(days=365)), "extra_info": ""
    }
    await test_client.post("/contacts/", json=contact_data_1, headers=headers)
    await test_client.post("/contacts/", json=contact_data_2, headers=headers)

    response = await test_client.get("/contacts/", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 2

    assert any(c["email"] == contact_data_1["email"] for c in data)
    assert any(c["email"] == contact_data_2["email"] for c in data)

@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_search_contacts(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    search_email = f"search_target_{uuid.uuid4()}@example.com"
    search_name = "SearchNameUnique"
    contact_data = {
        "first_name": search_name, "last_name": "SearchLast",
        "email": search_email,
        "phone": "5555555555", "birthday": str(date.today()), "extra_info": ""
    }
    await test_client.post("/contacts/", json=contact_data, headers=headers)

    response = await test_client.get(f"/contacts/search/?query={search_name}", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    contacts = response.json()
    assert isinstance(contacts, list)
    assert any(c["first_name"] == search_name for c in contacts)

    response_no_query = await test_client.get("/contacts/search/", headers=headers)
    assert response_no_query.status_code == status.HTTP_200_OK
    contacts_no_query = response_no_query.json()
    assert isinstance(contacts_no_query, list)
    assert any(c["email"] == search_email for c in contacts_no_query)

    response_empty_query = await test_client.get("/contacts/search/?query=", headers=headers)
    assert response_empty_query.status_code == status.HTTP_200_OK
    contacts_empty_query = response_empty_query.json()
    assert isinstance(contacts_empty_query, list)
    assert any(c["email"] == search_email for c in contacts_empty_query)

@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_get_upcoming_birthdays(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    today = date.today()
    in_5_days = today + timedelta(days=5)
    in_10_days = today + timedelta(days=10)
    in_35_days = today + timedelta(days=35)

    contact_today = {
        "first_name": "BirthdayToday", "last_name": "Test",
        "email": f"today_{uuid.uuid4()}@example.com",
        "phone": "3333333333", "birthday": str(today), "extra_info": ""
    }
    contact_5_days = {
        "first_name": "Birthday5Days", "last_name": "Test",
        "email": f"five_{uuid.uuid4()}@example.com",
        "phone": "4444444444", "birthday": str(in_5_days), "extra_info": ""
    }
    contact_10_days = {
        "first_name": "Birthday10Days", "last_name": "Test",
        "email": f"ten_{uuid.uuid4()}@example.com",
        "phone": "6666666666", "birthday": str(in_10_days), "extra_info": ""
    }
    contact_35_days = {
        "first_name": "Birthday35Days", "last_name": "Test",
        "email": f"thirtyfive_{uuid.uuid4()}@example.com",
        "phone": "7777777777", "birthday": str(in_35_days), "extra_info": ""
    }

    await test_client.post("/contacts/", json=contact_today, headers=headers)
    await test_client.post("/contacts/", json=contact_5_days, headers=headers)
    await test_client.post("/contacts/", json=contact_10_days, headers=headers)
    await test_client.post("/contacts/", json=contact_35_days, headers=headers)


    response = await test_client.get("/contacts/birthdays/upcoming", headers=headers)
    assert response.status_code == status.HTTP_200_OK
    birthdays = response.json()
    assert isinstance(birthdays, list)
    assert any(c["first_name"] == "BirthdayToday" for c in birthdays)
    assert any(c["first_name"] == "Birthday5Days" for c in birthdays)
    assert any(c["first_name"] == "Birthday10Days" for c in birthdays)
    assert not any(c["first_name"] == "Birthday35Days" for c in birthdays)

@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_create_contact_validation_error(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    invalid_contact_data = {
        "first_name": "Invalid", "last_name": "Email",
        "email": "invalid-email",
        "phone": "1234567890", "birthday": str(date.today()), "extra_info": ""
    }
    response = await test_client.post("/contacts/", json=invalid_contact_data, headers=headers)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "detail" in response.json()
    assert any("value is not a valid email address" in error["msg"] for error in response.json()["detail"])


@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_get_contact_not_found(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    non_existent_id = 999999
    response = await test_client.get(f"/contacts/{non_existent_id}", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Contact not found"

@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_update_contact_not_found(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    non_existent_id = 999999
    updated_data = {
        "first_name": "NotFound", "last_name": "Update",
        "email": f"notfound_update_{uuid.uuid4()}@example.com",
        "phone": "0000000000", "birthday": str(date.today()), "extra_info": ""
    }
    response = await test_client.put(f"/contacts/{non_existent_id}", json=updated_data, headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Contact not found"

@pytest.mark.asyncio
@patch("src.cache.redis_client.redis_client")
async def test_delete_contact_not_found(mock_redis_client: AsyncMock, test_client: AsyncClient, authenticated_user_token: dict):
    mock_redis_client.evalsha = AsyncMock(return_value=0)
    headers = authenticated_user_token

    non_existent_id = 999999
    response = await test_client.delete(f"/contacts/{non_existent_id}", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Contact not found"

@pytest.mark.asyncio
async def test_contacts_unauthorized_access(test_client: AsyncClient):
    response = await test_client.post("/contacts/", json={
        "first_name": "Anon", "last_name": "Contact", "email": "anon@example.com",
        "phone": "1234567890", "birthday": str(date.today())
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.get("/contacts/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.get("/contacts/1")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.put("/contacts/1", json={
        "first_name": "Anon Update", "last_name": "Contact", "email": "anon_upd@example.com",
        "phone": "1234567890", "birthday": str(date.today())
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.delete("/contacts/1")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.get("/contacts/search/?query=test")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = await test_client.get("/contacts/birthdays/upcoming")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED




