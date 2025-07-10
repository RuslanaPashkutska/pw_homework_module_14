import cloudinary
import cloudinary.uploader
from src.conf.config import settings


# Configure Cloudinary using settings from the config file
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
    """

    result = cloudinary.uploader.upload(file)
    return result["secure_url"]