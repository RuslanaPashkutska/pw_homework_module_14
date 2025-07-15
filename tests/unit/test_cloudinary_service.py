import unittest
from unittest.mock import patch, MagicMock
import io
from src.services.cloudinary_service import upload_avatar, CloudinaryApiError


class TestCloudinaryService(unittest.TestCase):

    def setUp(self):
        self.patcher_upload = patch('src.services.cloudinary_service.cloudinary.uploader.upload')
        self.mock_upload = self.patcher_upload.start()
        self.addCleanup(self.patcher_upload.stop)

    def test_upload_avatar_success(self):
        self.mock_upload.return_value = {"secure_url": "http://mocked.cloudinary.com/avatar.jpg"}

        mock_file = io.BytesIO(b"dummy image data")
        mock_file.name = "test_image.jpg"

        result_url = upload_avatar(mock_file)

        self.assertEqual(result_url, "http://mocked.cloudinary.com/avatar.jpg")

    def test_upload_avatar_upload_failure(self):
        self.mock_upload.side_effect = CloudinaryApiError("Simulated upload error")

        mock_file = io.BytesIO(b"dummy image data for failure")
        mock_file.name = "test_image.jpg"

        with self.assertRaises(CloudinaryApiError) as excinfo:
            upload_avatar(mock_file)

        self.assertIn("Simulated upload error", str(excinfo.exception))

    def test_upload_avatar_missing_secure_url_in_response(self):
        self.mock_upload.return_value = {"public_id": "test_id", "version": 1}

        mock_file = io.BytesIO(b"dummy image data for missing url")
        mock_file.name = "test_image.jpg"

        with self.assertRaises(KeyError):
            upload_avatar(mock_file)