import cloudinary
import cloudinary.uploader
from cloudinary.exceptions import Error as CloudinaryApiError
from src.conf.config import settings



cloudinary.config(
    cloud_name=settings.cloudinary_name,
    api_key=settings.cloudinary_api_key,
    api_secret=settings.cloudinary_api_secret,
    secure=True
)

def upload_avatar(file):
    """
    Uploads a user's avatar image to Cloudinary and returns the secure URL.

    Args:
        file: A file-like object representing the image to upload.

    Returns:
        str: The secure URL of the uploaded image.

    Raises:
        CloudinaryApiError: If the upload fails due to Cloudinary-related issues.
        KeyError: If 'secure_url' is not found in the response.
    """
    try:
        result = cloudinary.uploader.upload(file)
        return result["secure_url"]
    except CloudinaryApiError as e:
        raise CloudinaryApiError(f"Cloudinary upload failed: {e}")
    except KeyError:
        raise KeyError("Cloudinary response did not contain 'secure_url'")