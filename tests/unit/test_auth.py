
import unittest
import uuid
from fastapi import HTTPException
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta, timezone

from jose import jwt, JWTError
from src.auth import auth as auth_service
from src.database.models import User, VerificationToken


class MockSettings(MagicMock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.secret_key = "super_secret_test_key"
        self.refresh_secret_key = "super_refresh_secret_key"
        self.algorithm = "HS256"
        self.base_url = "http://testapi.com"
        self.frontend_base_url = "http://testfrontend.com"


class TestAuthService(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        super().setUp()
        self.mock_db = AsyncMock()
        self.mock_user = User(
            id=1,
            email="test@example.com",
            hashed_password="hashed_password",
            avatar=None,
            refresh_token=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_verified=True,
        )

        self.mock_unverified_user = User(
            id=2,
            email="unverified@example.com",
            hashed_password="hashed_password",
            avatar=None,
            refresh_token=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            is_verified=False,
        )

        self.mock_settings = MockSettings()
        auth_service.settings = self.mock_settings

    def test_get_password_hash(self):
        password = "mysecretpassword"
        hashed_password = auth_service.get_password_hash(password)
        self.assertIsInstance(hashed_password, str)
        self.assertTrue(hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"))

    def test_verify_password_success(self):
        password = "mysecretpassword"
        hashed_password = auth_service.get_password_hash(password)
        self.assertTrue(auth_service.verify_password(password, hashed_password))

    def test_verify_password_failure(self):
        password = "mysecretpassword"
        wrong_password = "wrongpassword"
        hashed_password = auth_service.get_password_hash(password)
        self.assertFalse(auth_service.verify_password(wrong_password, hashed_password))

    def test_create_access_token(self):
        data = {"sub": "test@example.com"}
        token = auth_service.create_access_token(data)
        self.assertIsInstance(token, str)
        decoded_payload = jwt.decode(token, self.mock_settings.secret_key, algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["sub"], "test@example.com")
        self.assertIn("exp", decoded_payload)
        self.assertGreater(decoded_payload["exp"], datetime.now(timezone.utc).timestamp())

    def test_create_access_token_with_expires_delta(self):
        data = {"sub": "test@example.com"}
        expires_delta = timedelta(minutes=10)
        token = auth_service.create_access_token(data, expires_delta)
        self.assertIsInstance(token, str)
        decoded_payload = jwt.decode(token, self.mock_settings.secret_key, algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["sub"], data["sub"])
        self.assertIn("exp", decoded_payload)
        expected_expire_timestamp = (datetime.now(timezone.utc) + expires_delta).timestamp()
        self.assertAlmostEqual(decoded_payload["exp"], expected_expire_timestamp, delta=5)

    def test_create_refresh_token(self):
        data = {"sub": "test@example.com"}
        token = auth_service.create_refresh_token(data)
        self.assertIsInstance(token, str)
        decoded_payload = jwt.decode(token, self.mock_settings.refresh_secret_key, algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["sub"], "test@example.com")
        self.assertIn("exp", decoded_payload)
        self.assertGreater(decoded_payload["exp"], datetime.now(timezone.utc).timestamp())

    @patch("src.auth.auth.repository_users")
    async def test_get_current_user_success(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": self.mock_user.email}, self.mock_settings.secret_key, algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email = AsyncMock(return_value=self.mock_user)

        current_user = await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        self.assertEqual(current_user.email, self.mock_user.email)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, self.mock_user.email)

    @patch("src.auth.auth.repository_users")
    async def test_get_current_user_invalid_token_jwt_error(self, mock_repository_users):
        invalid_token = "invalid.jwt.token"
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=invalid_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users")
    async def test_get_current_user_no_email_in_payload(self, mock_repository_users):
        encoded_token = jwt.encode({"invalid_key": "value"}, self.mock_settings.secret_key, algorithm=self.mock_settings.algorithm)
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users")
    async def test_get_current_user_user_not_found(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": "nonexistent@example.com"}, self.mock_settings.secret_key, algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email = AsyncMock(return_value=None)
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once()

    @patch("src.auth.auth.repository_users")
    async def test_get_current_user_email_not_verified(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": self.mock_unverified_user.email}, self.mock_settings.secret_key, algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email = AsyncMock(return_value=self.mock_unverified_user)
        with self.assertRaisesRegex(HTTPException, "Email not verified"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once()

    def test_create_email_verification_token_and_save(self):
        data = {"user_id": 1}
        token = auth_service.create_email_verification_token_and_save(data)
        self.assertIsInstance(token, str)
        decoded_payload = jwt.decode(token, self.mock_settings.refresh_secret_key, algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["user_id"], 1)
        self.assertIn("exp", decoded_payload)

    def test_create_email_verification_token(self):
        user_id = 1
        token = auth_service.create_email_verification_token(user_id)
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 36)
        try:
            uuid.UUID(token)
        except ValueError:
            self.fail("Token is not a valid UUID")

    @patch("src.auth.auth.repository_auth")
    async def test_save_verification_token(self, mock_repository_auth):
        user_id = 1
        token_str = "some_token_string"
        token_type = "email_verification"
        mock_repository_auth.create_verification_token = MagicMock()
        await auth_service.save_verification_token(user_id, token_str, token_type, self.mock_db)
        mock_repository_auth.create_verification_token.assert_called_once()
        args, _ = mock_repository_auth.create_verification_token.call_args
        created_token = args[0]
        self.assertIsInstance(created_token, VerificationToken)
        self.assertEqual(created_token.user_id, user_id)
        self.assertEqual(created_token.token, token_str)
        self.assertEqual(created_token.token_type, token_type)
        self.assertGreater(created_token.expires_at, datetime.now(timezone.utc))

    @patch("src.auth.auth.repository_users")
    @patch("src.auth.auth.repository_auth")
    async def test_verify_email_token_success(self, mock_repository_auth, mock_repository_users):
        mock_token = VerificationToken(
            id=1,
            user_id=self.mock_unverified_user.id,
            token="valid_token",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        mock_repository_auth.get_verification_token = AsyncMock(return_value=mock_token)
        mock_repository_users.get_user_by_id = AsyncMock(return_value=self.mock_unverified_user)
        mock_repository_users.update_user = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        verified_user = await auth_service.verify_email_token("valid_token", self.mock_db)
        self.assertIsNotNone(verified_user)
        self.assertTrue(verified_user.is_verified)
        mock_repository_auth.get_verification_token.assert_awaited_once_with("valid_token", "email_verification", self.mock_db)
        mock_repository_users.get_user_by_id.assert_awaited_once_with(self.mock_unverified_user.id, self.mock_db)
        mock_repository_users.update_user.assert_called_once_with(self.mock_unverified_user, self.mock_db)
        mock_repository_auth.delete_verification_token.assert_called_once_with(mock_token.id, self.mock_db)

    @patch("src.auth.auth.repository_users")
    @patch("src.auth.auth.repository_auth")
    async def test_verify_email_token_invalid_or_expired(self, mock_repository_auth, mock_repository_users):
        mock_repository_auth.get_verification_token = AsyncMock(return_value=None)
        mock_repository_users.get_user_by_id = AsyncMock()
        mock_repository_users.update_user = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        verified_user = await auth_service.verify_email_token("invalid_token", self.mock_db)
        self.assertIsNone(verified_user)
        mock_repository_auth.get_verification_token.assert_awaited_once_with("invalid_token", "email_verification", self.mock_db)
        mock_repository_users.get_user_by_id.assert_not_called()
        mock_repository_users.update_user.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()

    @patch("src.auth.auth.repository_users")
    @patch("src.auth.auth.repository_auth")
    async def test_verify_email_token_user_not_found(self, mock_repository_auth, mock_repository_users):
        mock_token = VerificationToken(
            id=1,
            user_id=999,
            token="valid_token",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        mock_repository_auth.get_verification_token = AsyncMock(return_value=mock_token)
        mock_repository_users.get_user_by_id = AsyncMock(return_value=None)
        mock_repository_users.update_user = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        verified_user = await auth_service.verify_email_token("valid_token", self.mock_db)
        self.assertIsNone(verified_user)
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_id.assert_awaited_once_with(999, self.mock_db)
        mock_repository_users.update_user.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()

    @patch("src.auth.auth.repository_auth")
    @patch("src.auth.auth.repository_users")
    async def test_create_password_reset_token_and_save_success(self, mock_repository_users, mock_repository_auth):
        mock_repository_users.get_user_by_email = AsyncMock(return_value=self.mock_user)
        mock_repository_auth.create_verification_token = MagicMock()
        token = await auth_service.create_password_reset_token_and_save(self.mock_user.email, self.mock_db)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_user.email, self.mock_db)
        mock_repository_auth.create_verification_token.assert_called_once()
        args, _ = mock_repository_auth.create_verification_token.call_args
        created_token = args[0]
        self.assertEqual(created_token.user_id, self.mock_user.id)
        self.assertEqual(created_token.token_type, "password_reset")

    @patch("src.auth.auth.repository_users")
    async def test_create_password_reset_token_and_save_user_not_found(self, mock_repository_users):
        mock_repository_users.get_user_by_email = AsyncMock(return_value=None)
        token = await auth_service.create_password_reset_token_and_save("noneexictent@example.com", self.mock_db)
        self.assertIsNone(token)
        mock_repository_users.get_user_by_email.assert_awaited_once_with("noneexictent@example.com", self.mock_db)

    @patch("src.auth.auth.get_password_hash")
    @patch("src.auth.auth.repository_auth")
    @patch("src.auth.auth.repository_users")
    async def test_reset_password_success(self, mock_repository_users, mock_repository_auth, mock_get_password_hash):
        mock_reset_token = VerificationToken(
            id=1,
            user_id=self.mock_user.id,
            token="valid_reset_token",
            token_type="password_reset",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        mock_repository_auth.get_verification_token = AsyncMock(return_value=mock_reset_token)
        mock_repository_users.get_user_by_id = AsyncMock(return_value=self.mock_user)
        mock_get_password_hash.return_value = "new_hashed_password"
        mock_repository_users.update_user_password = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        updated_user = await auth_service.reset_password("valid_reset_token", "new_password_123", self.mock_db)
        self.assertIsNotNone(updated_user)
        self.assertEqual(updated_user.id, self.mock_user.id)
        mock_repository_auth.get_verification_token.assert_awaited_once_with("valid_reset_token", "password_reset", self.mock_db)
        mock_repository_users.get_user_by_id.assert_awaited_once_with(self.mock_user.id, self.mock_db)
        mock_get_password_hash.assert_called_once_with("new_password_123")
        mock_repository_users.update_user_password.assert_called_once_with(self.mock_user.id, "new_hashed_password", self.mock_db)
        mock_repository_auth.delete_verification_token.assert_called_once_with(mock_reset_token.id, self.mock_db)

    @patch("src.auth.auth.repository_users")
    @patch("src.auth.auth.repository_auth")
    async def test_reset_password_invalid_or_expired_token(self, mock_repository_auth, mock_repository_users):
        mock_repository_auth.get_verification_token = AsyncMock(return_value=None)
        mock_repository_users.get_user_by_id = AsyncMock()
        mock_repository_users.update_user_password = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        updated_user = await auth_service.reset_password("invalid_token", "new_password_123", self.mock_db)
        self.assertIsNone(updated_user)
        mock_repository_auth.get_verification_token.assert_awaited_once_with("invalid_token", "password_reset", self.mock_db)
        mock_repository_users.get_user_by_id.assert_not_called()
        mock_repository_users.update_user_password.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()

    @patch("src.auth.auth.repository_users")
    @patch("src.auth.auth.repository_auth")
    async def test_reset_password_user_not_found(self, mock_repository_auth, mock_repository_users):
        mock_reset_token = VerificationToken(
            id=1,
            user_id=999,
            token="valid_reset_token",
            token_type="password_reset",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        mock_repository_auth.get_verification_token = AsyncMock(return_value=mock_reset_token)
        mock_repository_users.get_user_by_id = AsyncMock(return_value=None)
        mock_repository_users.update_user_password = MagicMock()
        mock_repository_auth.delete_verification_token = MagicMock()
        updated_user = await auth_service.reset_password("valid_reset_token", "new_password_123", self.mock_db)
        self.assertIsNone(updated_user)
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_id.assert_awaited_once_with(999, self.mock_db)
        mock_repository_users.update_user_password.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()


if __name__ == '__main__':
    unittest.main()








