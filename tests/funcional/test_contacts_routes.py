import pytest
from httpx import AsyncClient
from datetime import date

@pytest.mark.asyncio
async def test_create_and_manage_contact(test_client: AsyncClient, token):
    headers = {"Authorization": f"Bearer {token}"}

    contact_data = {
        "first_name": "Alice",
        "last_name": "Smith",
        "email": "alice@example.com",
        "phone": "1234567890",
        "birthday": str(date.today()),
        "extra_info": "Functional test contact"
    }

    response = await test_client.post("/contacts/", json=contact_data, headers=headers)
    assert response.status_code == 201
    contact = response.json()
    assert contact["email"] == "alice@example.com"
    contact_id = contact["id"]

    response = await test_client.get("/contacts/", headers=headers)
    assert response.status_code == 200
    assert any (c["id"] == contact_id for c in response.json())

    response = await  test_client.get(f"/contacts/{contact_id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == contact_id

    updated_data = {
        "first_name": "Alice",
        "last_name": "Johnson",
        "email": "alice@example.com",
        "phone": "1234567890",
        "birthday": str(date.today()),
        "extra_info": "Updated contact"
    }
    response = await test_client.put(f"/contacts/{contact_id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["last_name"] == "Johnson"

    response = await test_client.get("/contacts/search/?query=Alice", headers=headers)
    assert response.status_code == 200
    assert any("Alice" in c["first_name"] for c in response.json())

    response = await test_client.get("/contacts/birthdays/upcoming", headers=headers)
    assert response.status_code == 200

    response = await test_client.delete(f"/contacts/{contact_id}", headers=headers)
    assert response.status_code == 204

    response = await test_client.get(f"/contacts/{contact_id}", headers=headers)
    assert response.status_code == 404
