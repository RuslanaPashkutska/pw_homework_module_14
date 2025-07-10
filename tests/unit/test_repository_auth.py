import unittest
from unittest.mock import MagicMock, AsyncMock
from src.repository import auth as auth_repository
from src.database.models import User, VerificationToken
from datetime import datetime, timedelta, timezone

class TestAuthRepository(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.db = AsyncMock()
        self.token = VerificationToken(
            id=1,
            user_id=123,
            token="abc123",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
    async def test_create_verification_token(self):
        self.db.add = MagicMock()
        self.db.commit = AsyncMock()
        self.db.refresh = AsyncMock()

        result = await auth_repository.create_verification_token(self.token, self.db)

        self.db.add.assert_called_once_with(self.token)
        self.db.commit.assert_awaited_once()
        self.db.refresh.assert_awaited_once_with(self.token)
        self.assertEqual(result, self.token)


    async def test_get_verification_token(self):
        mock_result = MagicMock()
        mock_result.scalar_one_or_none = MagicMock(return_value=self.token)
        self.db.execute.return_value = mock_result

        result = await auth_repository.get_verification_token("abc123", "email_verification", self.db)

        self.db.execute.assert_awaited_once()
        self.assertEqual(result, self.token)

    async def test_delete_verification_token(self):
        self.db.execute = AsyncMock()
        self.db.commit = AsyncMock()

        await auth_repository.delete_verification_token(1, self.db)

        self.db.execute.assert_called_once()
        self.db.commit.assert_called_once()

if __name__ == '__main__':
    unittest.main()
