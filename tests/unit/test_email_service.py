import unittest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path
from pydantic import SecretStr
from jinja2 import Environment, FileSystemLoader
from src.services import email as email_service
from fastapi_mail import MessageType, ConnectionConfig, MessageSchema
from fastapi_mail.errors import ConnectionErrors

class TestEmailService(unittest.IsolatedAsyncioTestCase):

    def _setup_mock_settings(self, mock_settings):
        mock_settings.mail_username = "test_user"
        mock_settings.mail_password = SecretStr("test_pass")
        mock_settings.mail_from = "test_from@example.com"
        mock_settings.mail_port = 587
        mock_settings.mail_server = "smtp.test.com"
        mock_settings.mail_starttls = True
        mock_settings.mail_ssl = False
        mock_settings.base_url = "http://testapi.com"
        mock_settings.frontend_base_url = "http://testfrontend.com"
        mock_settings.mail_from_name = "Contacts App"
        mock_settings.template_folder = Path(__file__).parent.parent.parent / 'src' / 'services' / 'templates'

    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_email_verify_success(self, mock_settings, mock_fastmail_class):
        self._setup_mock_settings(mock_settings)

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance

        test_email = "recipient@example.com"
        test_user_name = "TestUser"
        test_token = "verify_token_123"
        test_email_type = "verify_email"

        await email_service.send_email(
            email=test_email,
            user_name=test_user_name,
            token=test_token,
            email_type=test_email_type
        )

        mock_fastmail_class.assert_called_once()
        args, _ = mock_fastmail_class.call_args
        called_conf = args[0]

        self.assertIsInstance(called_conf, ConnectionConfig)
        self.assertEqual(called_conf.MAIL_USERNAME, mock_settings.mail_username)
        self.assertEqual(str(called_conf.MAIL_PASSWORD.get_secret_value()), "test_pass")
        self.assertEqual(called_conf.MAIL_FROM, mock_settings.mail_from)
        self.assertEqual(called_conf.MAIL_PORT, mock_settings.mail_port)
        self.assertEqual(called_conf.MAIL_SERVER, mock_settings.mail_server)
        self.assertEqual(called_conf.MAIL_FROM_NAME, mock_settings.mail_from_name)
        self.assertEqual(called_conf.MAIL_STARTTLS, mock_settings.mail_starttls)
        self.assertEqual(called_conf.MAIL_SSL_TLS, mock_settings.mail_ssl)
        self.assertEqual(called_conf.USE_CREDENTIALS, True)  # Esto está hardcodeado en tu servicio
        self.assertEqual(called_conf.VALIDATE_CERTS, True)  # Esto está hardcodeado en tu servicio
        self.assertEqual(called_conf.TEMPLATE_FOLDER,
                         Path(__file__).parent.parent.parent / 'src' / 'services' / 'templates')


        mock_fastmail_instance.send_message.assert_called_once()

        message_schema = mock_fastmail_instance.send_message.call_args[0][0]
        kwargs = mock_fastmail_instance.send_message.call_args[1]

        self.assertEqual(message_schema.subject, "Verify your email - Contacts App")
        self.assertEqual(message_schema.recipients, [test_email])
        self.assertEqual(message_schema.subtype, MessageType.html)
        self.assertEqual(kwargs["template_name"], "email_verify.html")

        expected_link = f"{mock_settings.base_url}/auth/verify_email/{test_token}"
        self.assertEqual(message_schema.template_body["host"], mock_settings.base_url)
        self.assertEqual(message_schema.template_body["user_name"], test_user_name)
        self.assertEqual(message_schema.template_body["link"], expected_link)
        self.assertIn(test_email, message_schema.recipients)

    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_email_rest_password_success(self, mock_settings, mock_fastmail_class):
        self._setup_mock_settings(mock_settings)

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance

        test_email = "reset@example.com"
        test_user_name = "ResetUser"
        test_token = "reset_token_456"
        test_email_type = "reset_password"

        await email_service.send_email(
            email=test_email,
            user_name=test_user_name,
            token=test_token,
            email_type=test_email_type
        )

        mock_fastmail_class.assert_called_once()
        args, _ = mock_fastmail_class.call_args
        called_conf = args[0]
        self.assertIsInstance(called_conf, ConnectionConfig)

        mock_fastmail_instance.send_message.assert_called_once()

        message_schema = mock_fastmail_instance.send_message.call_args[0][0]
        kwargs = mock_fastmail_instance.send_message.call_args[1]

        self.assertEqual(message_schema.subject, "Reset your password - Contacts App")
        self.assertEqual(message_schema.recipients, [test_email])
        self.assertEqual(message_schema.subtype, MessageType.html)
        self.assertEqual(kwargs["template_name"], "email_reset_password.html")

        expected_link = f"{email_service.settings.base_url}/auth/reset_password?token={test_token}"
        self.assertEqual(message_schema.template_body["host"], mock_settings.base_url)
        self.assertEqual(message_schema.template_body["user_name"], test_user_name)
        self.assertEqual(message_schema.template_body["link"], expected_link)


    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_email_invalid_type(self, mock_settings, mock_fastmail_class):
        mock_settings.base_url = "http://testapi.com"

        with self.assertRaisesRegex(ValueError, "Invalid email type specified."):
            await email_service.send_email(
                email="invalid@examole.com",
                user_name="Invalid",
                token="token",
                email_type="unknown_type"
            )

        mock_fastmail_class.assert_not_called()


    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_email_connection_error(self, mock_settings, mock_fastmail_class):
        self._setup_mock_settings(mock_settings)

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance
        mock_fastmail_instance.send_message.side_effect = email_service.ConnectionErrors("Simulated Connection Error")

        with patch("builtins.print") as mock_print:
            await email_service.send_email(
                email="connection@example.com",
                user_name="ConnErr",
                token="token",
                email_type="verify_email"
            )

            mock_print.assert_called_once_with(
                f"Failed to send email to connection@example.com: Connection error - Simulated Connection Error"
            )
            mock_fastmail_class.assert_called_once()
            mock_fastmail_instance.send_message.assert_called_once()


    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_email_generic_exception(self, mock_settings, mock_fastmail_class):
        self._setup_mock_settings(mock_settings)

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance
        mock_fastmail_instance.send_message.side_effect = Exception("Some unexpected error")

        with patch("builtins.print") as mock_print:
            await email_service.send_email(
                email="generic@example.com",
                user_name="GenericErr",
                token="token",
                email_type="verify_email"
            )
            mock_print.assert_called_once_with(
                f"Failed to send email to generic@example.com: An unexpected error occurred - Some unexpected error"
            )
            mock_fastmail_class.assert_called_once()
            mock_fastmail_instance.send_message.assert_called_once()


    @patch("src.services.email.FileSystemLoader")
    @patch("src.services.email.Environment")
    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_rest_password_email_success(self, mock_settings, mock_fastmail_class, mock_environment_class, mock_file_system_loader_class):
        self._setup_mock_settings(mock_settings)

        mock_template = MagicMock()
        mock_template.render.return_value = "<html>Reset HTML</html>"
        mock_env_instance = MagicMock()
        mock_env_instance.get_template.return_value = mock_template
        mock_environment_class.return_value = mock_env_instance

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance

        mock_fs_loader_instance = MagicMock()
        mock_file_system_loader_class.return_value = mock_fs_loader_instance

        test_email = "reset_standalone@example.com"
        test_token = "standalone_token_789"

        with patch("builtins.print") as mock_print:
            await email_service.send_reset_password_email(email=test_email, token=test_token)
            mock_print.assert_called_once_with(f"Reset password email sent successfully to {test_email}")

        mock_file_system_loader_class.assert_called_once_with(mock_settings.template_folder)

        mock_environment_class.assert_called_once_with(loader=mock_fs_loader_instance)
        mock_env_instance.get_template.assert_called_once_with("reset_password.html")
        expected_reset_link = f"{mock_settings.frontend_base_url}/reset-password?token={test_token}"
        mock_template.render.assert_called_once_with(reset_link=expected_reset_link)

        mock_fastmail_class.assert_called_once()
        args, _ = mock_fastmail_class.call_args
        called_conf = args[0]
        self.assertIsInstance(called_conf, ConnectionConfig)
        self.assertEqual(called_conf.MAIL_USERNAME, mock_settings.mail_username)

        mock_fastmail_instance.send_message.assert_called_once()

        message_schema = mock_fastmail_instance.send_message.call_args[0][0]

        self.assertEqual(message_schema.subject, "Reset your password")
        self.assertEqual(message_schema.recipients, [test_email])
        self.assertEqual(message_schema.body, "<html>Reset HTML</html>")
        self.assertEqual(message_schema.subtype, MessageType.html)


    @patch("src.services.email.Environment")
    @patch("src.services.email.FastMail")
    @patch("src.services.email.settings", autospec=True)
    async def test_send_reset_password_email_failure(self, mock_settings, mock_fastmail_class, mock_environment_class):
        self._setup_mock_settings(mock_settings)

        mock_template = MagicMock()
        mock_template.render.return_value = "<html>Reset HTML</html>"

        mock_env_instance = MagicMock()
        mock_env_instance.get_template.return_value = mock_template
        mock_environment_class.return_value = mock_env_instance

        mock_fastmail_instance = AsyncMock()
        mock_fastmail_class.return_value = mock_fastmail_instance
        mock_fastmail_instance.send_message.side_effect = Exception("Jinja2 render error or other email sending issue")

        with patch("builtins.print") as mock_print:
            with self.assertRaises(Exception) as cm:
                await email_service.send_reset_password_email(email="fail@example.com", token="fail_token")

            self.assertIn("Jinja2 render error or other email sending issue", str(cm.exception))

            mock_print.assert_called_once_with(
                f"Failed to send reset password email to fail@example.com: An unexpected error occurred - Jinja2 render error or other email sending issue"
            )


        mock_fastmail_instance.send_message.assert_called_once()
        mock_fastmail_class.assert_called_once()



if __name__ == '__main__':
    unittest.main()





