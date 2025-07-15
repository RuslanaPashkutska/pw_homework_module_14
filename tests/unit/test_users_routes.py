import pytest

from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from io import BytesIO

from src.main import app
from src.database.db import get_db

client = TestClient(app)

@pytest.fixture
def mock_db_session():
    """
    Fixture para mockear la sesión de la base de datos.
    """
    mock_session = MagicMock()
    yield mock_session

@pytest.fixture(autouse=True)
def override_get_db_dependency(mock_db_session):
    """
    Sobrescribe la dependencia get_db para que use el mock_db_session.
    """
    app.dependency_overrides[get_db] = lambda: mock_db_session
    yield

    app.dependency_overrides.clear()

class TestUserRoutes:
    def test_get_users(self):
        """
        Test the /users/ GET endpoint.
        """
        response = client.get("/users/")
        assert response.status_code == 200
        assert response.json() == {"message": "List of users"}

    def test_get_user(self):
        """
        Test the /users/{user_id} GET endpoint.
        """
        user_id = 1
        response = client.get(f"/users/{user_id}")
        assert response.status_code == 200
        assert response.json() == {"message": f"Details of user {user_id}"}

    @patch("src.routes.users.upload_avatar")
    def test_update_avatar_success(self, mock_upload_avatar, mock_db_session):
        """
        Test the /users/avatar POST endpoint for successful avatar upload.
        """
        mock_uploaded_url = "http://mocked.cloudinary.com/new_avatar.jpg"
        mock_upload_avatar.return_value = mock_uploaded_url

        test_file_content = b"fake image data"
        test_file = BytesIO(test_file_content)
        test_file.name = "avatar.jpg"

        response = client.post(
            "/users/avatar",
            files={"file": ("avatar.jpg", test_file, "image/jpeg")}
        )

        assert response.status_code == 200
        assert response.json() == {"avatar_url": mock_uploaded_url}

        mock_upload_avatar.assert_called_once()

    @patch("src.routes.users.upload_avatar")
    def test_update_avatar_upload_failure(self, mock_upload_avatar, mock_db_session):
        """
        Test the /users/avatar POST endpoint when avatar upload fails.
        """
        mock_upload_avatar.side_effect = Exception("Cloudinary upload failed")

        test_file_content = b"another fake image data"
        test_file = BytesIO(test_file_content)
        test_file.name = "error_avatar.png"

        response = client.post(
            "/users/avatar",
            files={"file": ("error_avatar.png", test_file, "image/png")}
        )

        assert response.status_code == 500

        mock_upload_avatar.assert_called_once()