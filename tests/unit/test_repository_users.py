import unittest
from unittest.mock import AsyncMock, MagicMock
from src.repository import users as users_repository
from src.database import models
from src.schemas.user import UserCreate

class TestUserRepository(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.db = AsyncMock()
        self.user_id = 1
        self.user_email= "test@example.com"
        self.hashed_password = "hashed_password"

        self.user_data = UserCreate(email=self.user_email, password="password123")

    async def test_get_user_by_email(self):
        mock_user = MagicMock()
        mock_user.id = self.user_id
        mock_user.email = self.user_email
        mock_user.hashed_password = self.hashed_password
        mock_user.is_verified = False

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        self.db.execute.return_value = mock_result
        result = await users_repository.get_user_by_email(self.db, self.user_email)
        self.assertIsNotNone(result)
        self.assertEqual(result.email, self.user_email)
        self.assertEqual(result.id, self.user_id)
        self.db.execute.assert_called_once()

    async def test_get_user_by_email_not_found(self):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        self.db.execute.return_value = mock_result
        result = await users_repository.get_user_by_email(self.db, "nonexistent@example.com")
        self.assertIsNone(result)
        self.db.execute.assert_called_once()

    async def test_get_user_by_id(self):
        mock_user = MagicMock()
        mock_user.id = self.user_id
        mock_user.email = self.user_email
        mock_user.hashed_password = self.hashed_password
        mock_user.is_verified = True

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        self.db.execute.return_value = mock_result
        result = await users_repository.get_user_by_id(self.db, self.user_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.user_id)
        self.assertEqual(result.email, self.user_email)
        self.db.execute.assert_called_once()

    async def test_get_user_by_id_not_found(self):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        self.db.execute.return_value = mock_result
        result = await users_repository.get_user_by_id(self.db, 999)
        self.assertIsNone(result)
        self.db.execute.assert_called_once()

    async def test_create_user(self):
        mock_user_instance_in_db = MagicMock(spec=models.User)
        mock_user_instance_in_db.email = self.user_email
        mock_user_instance_in_db.hashed_password = self.hashed_password
        mock_user_instance_in_db.is_verified = False

        with unittest.mock.patch('src.repository.users.models.User', return_value=mock_user_instance_in_db) as mock_User_class:

            async def set_id_on_refresh_side_effect(obj):
                obj.id = self.user_id

            self.db.refresh.side_effect = set_id_on_refresh_side_effect

            result = await users_repository.create_user(self.db, self.user_data, self.hashed_password)

            self.assertIsNotNone(result)
            self.assertEqual(result.email, self.user_email)
            self.assertEqual(result.hashed_password, self.hashed_password)
            self.assertEqual(result.id, self.user_id)
            mock_User_class.assert_called_once_with(email=self.user_email, hashed_password=self.hashed_password)
            self.db.add.assert_called_once_with(mock_user_instance_in_db)
            self.db.commit.assert_called_once()
            self.db.refresh.assert_called_once_with(mock_user_instance_in_db)

    async def test_update_user_is_verified(self):
        mock_user = MagicMock()
        mock_user.id = self.user_id
        mock_user.email = self.user_email
        mock_user.is_verified = False

        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = mock_user
        self.db.execute.return_value = mock_get_user_result
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock(return_value=mock_user)

        updated_user = await users_repository.update_user_is_verified(self.db, self.user_id, True)

        self.assertIsNotNone(updated_user)
        self.assertTrue(updated_user.is_verified)
        self.db.commit.assert_called_once()
        self.db.refresh.assert_called_once_with(mock_user)

    async def test_update_user_is_verified_not_found(self):
        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = None
        self.db.execute.return_value = mock_get_user_result

        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()

        updated_user = await users_repository.update_user_is_verified(self.db, 999, True)

        self.assertIsNone(updated_user)
        self.db.commit.assert_not_called()
        self.db.refresh.assert_not_called()

    async  def test_update_user_password(self):
        mock_user = MagicMock()
        mock_user.id = self.user_id
        mock_user.email = self.user_email
        mock_user.hashed_password = "old_hashed_password"

        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = mock_user
        self.db.execute.return_value = mock_get_user_result
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock(return_value=mock_user)

        new_hashed_password = "new_hashed_password"
        updated_user = await users_repository.update_user_password(self.db, self.user_id, new_hashed_password)

        self.assertIsNotNone(updated_user)
        self.assertEqual(updated_user.hashed_password, new_hashed_password)
        self.db.commit.assert_called_once()
        self.db.refresh.assert_called_once_with(mock_user)

    async def test_update_user_password_not_found(self):
        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = None
        self.db.execute.return_value = mock_get_user_result

        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()

        updated_user = await users_repository.update_user_password(self.db, 999, "new_pass")

        self.assertIsNone(updated_user)
        self.db.commit.assert_not_called()
        self.db.refresh.assert_not_called()

    async def test_update_user_avatar(self):
        mock_user = MagicMock()
        mock_user.id = self.user_id
        mock_user.email = self.user_email
        mock_user.avatar = None

        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = mock_user
        self.db.execute.return_value = mock_get_user_result
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock(return_value=mock_user)

        avatar_url = "http://example.com/avatar.jpg"
        updated_user = await users_repository.update_user_avatar(self.db, self.user_id, avatar_url)

        self.assertIsNotNone(updated_user)
        self.assertEqual(updated_user.avatar, avatar_url)
        self.db.commit.assert_called_once()
        self.db.refresh.assert_called_once_with(mock_user)

    async def test_update_user_avatar_not_found(self):
        mock_get_user_result = MagicMock()
        mock_get_user_result.scalar_one_or_none.return_value = None
        self.db.execute.return_value = mock_get_user_result

        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()

        updated_user = await users_repository.update_user_avatar(self.db, 999, "http://example.com/avatar.jpg")

        self.assertIsNone(updated_user)
        self.db.commit.assert_not_called()
        self.db.refresh.assert_not_called()

if __name__ == '__main__':
    unittest.main()








