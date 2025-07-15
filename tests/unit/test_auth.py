import pytest
import unittest
import uuid
from fastapi import HTTPException, status
from unittest.mock import MagicMock, AsyncMock, patch

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch
from jose import jwt
from datetime import datetime, timedelta, timezone

from src.auth.auth import create_email_verification_token_and_save, verify_email_token
from src.conf.config import settings
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
        self.settings_patcher = patch('src.auth.auth.settings', new=self.mock_settings)
        self.settings_patcher.start()

    def tearDown(self):
        super().tearDown()
        self.settings_patcher.stop()

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
        self.assertGreater(decoded_payload["exp"], datetime.now(timezone.utc).timestamp() - 5)

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
        decoded_payload = jwt.decode(token, self.mock_settings.refresh_secret_key,
                                     algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["sub"], "test@example.com")
        self.assertIn("exp", decoded_payload)
        self.assertGreater(decoded_payload["exp"], datetime.now(timezone.utc).timestamp() - 5)

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_get_current_user_success(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": self.mock_user.email}, self.mock_settings.secret_key,
                                   algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email.return_value = self.mock_user

        current_user = await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        self.assertEqual(current_user.email, self.mock_user.email)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, self.mock_user.email)

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_get_current_user_invalid_token_jwt_error(self, mock_repository_users):
        invalid_token = "invalid.jwt.token"
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=invalid_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_get_current_user_no_email_in_payload(self, mock_repository_users):
        encoded_token = jwt.encode({"invalid_key": "value"}, self.mock_settings.secret_key,
                                   algorithm=self.mock_settings.algorithm)
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_get_current_user_user_not_found(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": "nonexistent@example.com"}, self.mock_settings.secret_key,
                                   algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email.return_value = None
        with self.assertRaisesRegex(HTTPException, "Could not validate credentials"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_get_current_user_email_not_verified(self, mock_repository_users):
        encoded_token = jwt.encode({"sub": self.mock_unverified_user.email}, self.mock_settings.secret_key,
                                   algorithm=self.mock_settings.algorithm)
        mock_repository_users.get_user_by_email.return_value = self.mock_unverified_user
        with self.assertRaisesRegex(HTTPException, "Email not verified"):
            await auth_service.get_current_user(token=encoded_token, db=self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once()

    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_create_email_verification_token_and_save(self, mock_repo_users, mock_repo_auth):
        mock_repo_users.get_user_by_email.return_value = self.mock_user
        mock_repo_auth.create_verification_token = AsyncMock()

        token = await auth_service.create_email_verification_token_and_save(self.mock_user.email, self.mock_db)

        self.assertIsInstance(token, str)
        decoded_payload = jwt.decode(token, self.mock_settings.secret_key, algorithms=[self.mock_settings.algorithm])
        self.assertEqual(decoded_payload["sub"], self.mock_user.email)
        self.assertEqual(decoded_payload["type"], "email_verification")
        self.assertIn("exp", decoded_payload)
        mock_repo_users.get_user_by_email.assert_awaited_once_with(self.mock_db, self.mock_user.email)
        mock_repo_auth.create_verification_token.assert_awaited_once()

    @patch("src.auth.auth.save_verification_token", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users.get_user_by_email", new_callable=AsyncMock)
    async def test_create_email_verification_token_and_save_with_expires_delta(
            self,
            mock_get_user_by_email,
            mock_save_verification_token,
    ):
        mock_user = AsyncMock()
        mock_user.id = 123
        mock_get_user_by_email.return_value = mock_user

        mock_db = AsyncMock()
        expires = timedelta(days=3)

        token = await create_email_verification_token_and_save("test@example.com", mock_db, expires)

        self.assertIsInstance(token, str)
        mock_get_user_by_email.assert_awaited_once()
        mock_save_verification_token.assert_awaited_once()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_create_email_verification_token_and_save_user_not_found(self, mock_repo_users):
        mock_repo_users.get_user_by_email.return_value = None
        with self.assertRaisesRegex(HTTPException, "User not found."):
            await auth_service.create_email_verification_token_and_save("nonexistent@example.com", self.mock_db)
        mock_repo_users.get_user_by_email.assert_awaited_once_with(self.mock_db, "nonexistent@example.com")

    def test_create_email_verification_token(self):
        user_id = 1
        token = auth_service.create_email_verification_token(user_id)
        self.assertIsInstance(token, str)
        self.assertEqual(len(token), 36)
        try:
            uuid.UUID(token)
        except ValueError:
            self.fail("Token is not a valid UUID")

    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    async def test_save_verification_token(self, mock_repository_auth):
        user_id = 1
        token_str = "some_token_string"
        token_type = "email_verification"
        mock_repository_auth.create_verification_token.return_value = None
        await auth_service.save_verification_token(user_id, token_str, token_type, self.mock_db)
        mock_repository_auth.create_verification_token.assert_awaited_once()
        args, _ = mock_repository_auth.create_verification_token.call_args
        created_token = args[0]
        self.assertIsInstance(created_token, VerificationToken)
        self.assertEqual(created_token.user_id, user_id)
        self.assertEqual(created_token.token, token_str)
        self.assertEqual(created_token.token_type, token_type)
        self.assertGreater(created_token.expires_at, datetime.now(timezone.utc) - timedelta(seconds=1))

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_verify_email_token_success(self, mock_jwt_decode, mock_repository_auth, mock_repository_users):
        email_to_verify = self.mock_unverified_user.email

        mock_jwt_decode.return_value = {"sub": email_to_verify, "type": "email_verification"}

        mock_token_db = MagicMock(
            id=1,
            user_id=self.mock_unverified_user.id,
            token="any_jwt_token_string",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user=self.mock_unverified_user
        )

        mock_repository_auth.get_verification_token.return_value = mock_token_db
        mock_repository_users.get_user_by_email.return_value = self.mock_unverified_user

        verified_user_after_update_mock = MagicMock()
        for attr, value in self.mock_unverified_user.__dict__.items():
            if not attr.startswith('_sa_instance_state'):
                setattr(verified_user_after_update_mock, attr, value)
        verified_user_after_update_mock.is_verified = True

        mock_repository_users.update_user_is_verified.return_value = verified_user_after_update_mock

        mock_repository_users.update_user_is_verified = AsyncMock(return_value=verified_user_after_update_mock)

        mock_repository_auth.delete_verification_token = AsyncMock()

        verified_user = await auth_service.verify_email_token("valid_jwt_token_input", self.mock_db)

        # Assertions
        self.assertIsNotNone(verified_user)
        self.assertEqual(verified_user.email, email_to_verify)
        self.assertTrue(verified_user.is_verified)

        mock_jwt_decode.assert_called_once_with("valid_jwt_token_input", self.mock_settings.secret_key,
                                                algorithms=[self.mock_settings.algorithm])
        mock_repository_auth.get_verification_token.assert_awaited_once_with("valid_jwt_token_input",
                                                                             "email_verification", self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, email_to_verify)
        mock_repository_users.update_user_is_verified.assert_awaited_once_with(self.mock_db,
                                                                               self.mock_unverified_user.id, True)
        mock_repository_auth.delete_verification_token.assert_awaited_once_with(mock_token_db.id, self.mock_db)

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_verify_email_token_invalid_or_expired(self, mock_jwt_decode, mock_repository_auth,
                                                         mock_repository_users):
        mock_jwt_decode.side_effect = JWTError
        with self.assertRaisesRegex(HTTPException, "Invalid or expired verification token"):
            await auth_service.verify_email_token("invalid_jwt", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_not_called()
        mock_repository_users.get_user_by_email.assert_not_called()
        mock_jwt_decode.reset_mock(side_effect=True)

        mock_jwt_decode.return_value = {"sub": "any@example.com", "type": "email_verification"}
        mock_repository_auth.get_verification_token.return_value = None
        with self.assertRaisesRegex(HTTPException, "Invalid or expired verification token"):
            await auth_service.verify_email_token("non_existent_token", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_not_called()
        mock_jwt_decode.reset_mock(side_effect=True)
        mock_repository_auth.get_verification_token.reset_mock(return_value=None)

        expired_token_mock = MagicMock(
            user_id=1,
            token="expired_jwt_token",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        mock_jwt_decode.return_value = {"sub": "expired@example.com", "type": "email_verification"}
        mock_repository_auth.get_verification_token.return_value = expired_token_mock
        with self.assertRaisesRegex(HTTPException, "Invalid or expired verification token"):
            await auth_service.verify_email_token("expired_token", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_verify_email_token_user_not_found(self, mock_jwt_decode, mock_repository_auth,
                                                     mock_repository_users):
        email_from_payload = "notfound@example.com"
        mock_jwt_decode.return_value = {"sub": email_from_payload, "type": "email_verification"}
        mock_token_db = MagicMock(
            id=1,
            user_id=999,
            token="token_for_nonexistent_user",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        mock_repository_auth.get_verification_token.return_value = mock_token_db
        mock_repository_users.get_user_by_email.return_value = None

        with self.assertRaisesRegex(HTTPException, "Invalid or expired verification token"):
            await auth_service.verify_email_token("token_for_nonexistent_user", self.mock_db)

        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, email_from_payload)
        mock_repository_users.update_user_is_verified.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()


    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_verify_email_token_already_verified(self, mock_jwt_decode, mock_repository_auth,
                                                       mock_repository_users):
        email_already_verified = self.mock_user.email
        mock_jwt_decode.return_value = {"sub": email_already_verified, "type": "email_verification"}

        mock_token_db = MagicMock(
            id=1,
            user_id=self.mock_user.id,
            token="valid_token_already_verified",
            token_type="email_verification",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user=self.mock_user
        )

        mock_repository_auth.get_verification_token.return_value = mock_token_db
        mock_repository_users.get_user_by_email.return_value = self.mock_user

        with self.assertRaisesRegex(HTTPException, "Email already verified"):
            await auth_service.verify_email_token("valid_token_already_verified", self.mock_db)

        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, email_already_verified)
        mock_repository_users.update_user_is_verified.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()


    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_create_password_reset_token_and_save_success(self, mock_repository_users, mock_repository_auth):
        mock_repository_users.get_user_by_email.return_value = self.mock_user
        mock_repository_auth.create_verification_token = AsyncMock()
        token = await auth_service.create_password_reset_token_and_save(self.mock_user.email, self.mock_db)
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, self.mock_user.email)
        mock_repository_auth.create_verification_token.assert_awaited_once()
        args, _ = mock_repository_auth.create_verification_token.call_args
        created_token = args[0]
        self.assertEqual(created_token.user_id, self.mock_user.id)
        self.assertEqual(created_token.token_type, "password_reset")

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    async def test_create_password_reset_token_and_save_user_not_found(self, mock_repository_users):
        mock_repository_users.get_user_by_email.return_value = None
        with self.assertRaisesRegex(HTTPException, "User not found."):
            await auth_service.create_password_reset_token_and_save("nonexistent@example.com", self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, "nonexistent@example.com")

    @patch("src.auth.auth.get_password_hash")
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_reset_password_success(self, mock_jwt_decode, mock_repository_users, mock_repository_auth,
                                          mock_get_password_hash):
        email_to_reset = self.mock_user.email
        mock_jwt_decode.return_value = {"sub": email_to_reset, "type": "password_reset"}

        mock_reset_token_db = MagicMock(
            id=1,
            user_id=self.mock_user.id,
            token="valid_reset_token",
            token_type="password_reset",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            user=self.mock_user
        )
        mock_repository_auth.get_verification_token.return_value = mock_reset_token_db
        mock_repository_users.get_user_by_email.return_value = self.mock_user
        mock_get_password_hash.return_value = "new_hashed_password"

        self.mock_db.commit = AsyncMock()
        self.mock_db.refresh = AsyncMock()

        mock_repository_auth.delete_verification_token = AsyncMock()

        original_hashed_password = self.mock_user.hashed_password

        updated_user = await auth_service.reset_password("valid_reset_token", "new_password_123", self.mock_db)

        self.assertIsNotNone(updated_user)
        self.assertEqual(updated_user.id, self.mock_user.id)

        self.assertEqual(updated_user.hashed_password, "new_hashed_password")
        self.assertNotEqual(original_hashed_password, updated_user.hashed_password)

        mock_jwt_decode.assert_called_once_with("valid_reset_token", self.mock_settings.secret_key,
                                                algorithms=[self.mock_settings.algorithm])
        mock_repository_auth.get_verification_token.assert_awaited_once_with("valid_reset_token", "password_reset",
                                                                             self.mock_db)
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, email_to_reset)
        mock_get_password_hash.assert_called_once_with("new_password_123")

        self.mock_db.commit.assert_awaited_once()
        self.mock_db.refresh.assert_awaited_once_with(self.mock_user)

        mock_repository_auth.delete_verification_token.assert_awaited_once_with(mock_reset_token_db.id, self.mock_db)

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_reset_password_invalid_or_expired_token(self, mock_jwt_decode, mock_repository_auth,
                                                           mock_repository_users):
        mock_jwt_decode.side_effect = JWTError
        with self.assertRaisesRegex(HTTPException, "Invalid or expired reset token"):
            await auth_service.reset_password("invalid_jwt", "new_password", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_not_called()
        mock_repository_users.get_user_by_email.assert_not_called()
        mock_jwt_decode.reset_mock(side_effect=True)

        mock_jwt_decode.return_value = {"sub": "any@example.com", "type": "password_reset"}
        mock_repository_auth.get_verification_token.return_value = None  # Simulate token not found
        with self.assertRaisesRegex(HTTPException, "Invalid or expired reset token"):
            await auth_service.reset_password("non_existent_token", "new_password", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_not_called()
        mock_jwt_decode.reset_mock(side_effect=True)
        mock_repository_auth.get_verification_token.reset_mock(return_value=None)

        expired_token_mock = MagicMock(
            user_id=1,
            token="expired_token",
            token_type="password_reset",
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        mock_jwt_decode.return_value = {"sub": "expired@example.com", "type": "password_reset"}
        mock_repository_auth.get_verification_token.return_value = expired_token_mock
        with self.assertRaisesRegex(HTTPException, "Invalid or expired reset token"):
            await auth_service.reset_password("expired_token", "new_password", self.mock_db)
        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_not_called()

    @patch("src.auth.auth.repository_users", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_auth", new_callable=AsyncMock)
    @patch("src.auth.auth.jwt.decode")
    async def test_reset_password_user_not_found(self, mock_jwt_decode, mock_repository_auth, mock_repository_users):
        email_from_payload = "nonexistent_user@example.com"
        mock_jwt_decode.return_value = {"sub": email_from_payload, "type": "password_reset"}
        mock_reset_token_db = MagicMock(
            id=1,
            user_id=999,
            token="valid_reset_token_for_nonexistent_user",
            token_type="password_reset",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        mock_repository_auth.get_verification_token.return_value = mock_reset_token_db
        mock_repository_users.get_user_by_email.return_value = None

        with self.assertRaisesRegex(HTTPException, "Invalid or expired reset token"):
            await auth_service.reset_password("valid_reset_token_for_nonexistent_user", "new_password_123",
                                              self.mock_db)

        mock_jwt_decode.assert_called_once()
        mock_repository_auth.get_verification_token.assert_awaited_once()
        mock_repository_users.get_user_by_email.assert_awaited_once_with(self.mock_db, email_from_payload)
        mock_repository_users.update_user_password.assert_not_called()
        mock_repository_auth.delete_verification_token.assert_not_called()

    def test_make_aware_already_aware(self):
        """
        Prueba make_aware cuando el datetime de entrada ya es consciente de la zona horaria.
        """
        aware_dt = datetime.now(timezone.utc)

        result_dt = auth_service.make_aware(aware_dt)

        self.assertEqual(result_dt, aware_dt)
        self.assertIsNotNone(result_dt.tzinfo)
        self.assertEqual(result_dt.tzinfo, timezone.utc)

class TestVerifyEmailToken(IsolatedAsyncioTestCase):

    @patch("src.auth.auth.repository_auth.get_verification_token", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users.get_user_by_email", new_callable=AsyncMock)
    async def test_verify_email_token_invalid_type(self, mock_get_user_by_email, mock_get_token):
        payload = {
            "sub": "test@example.com",
            "type": "not_email_verification",
            "exp": (datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

        db_mock = AsyncMock()

        with self.assertRaises(Exception) as context:
            await verify_email_token(token, db_mock)

        self.assertEqual(context.exception.detail, "Invalid or expired verification token")

    @patch("src.auth.auth.repository_auth.get_verification_token", new_callable=AsyncMock)
    @patch("src.auth.auth.repository_users.get_user_by_email", new_callable=AsyncMock)
    async def test_verify_email_token_missing_email(self, mock_get_user_by_email, mock_get_token):
        payload = {
            "type": "email_verification",
            "exp": (datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()
        }
        token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

        db_mock = AsyncMock()

        with self.assertRaises(Exception) as context:
            await verify_email_token(token, db_mock)

        self.assertEqual(context.exception.detail, "Invalid or expired verification token")

if __name__ == '__main__':
    unittest.main()