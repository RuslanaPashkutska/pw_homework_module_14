from fastapi import APIRouter, UploadFile, File, Depends
from src.services.cloudinary_service import upload_avatar
from src.database.db import get_db
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(
    prefix="/users",
    tags=["users"]
)

@router.get("/")
async def get_users():
    """
    Retrieve a list of all users.

    :return: Message indicating the list of users.
    """
    return {"message": "List of users"}

@router.get("/{user_id}")
async def get_user(user_id: int):
    """
    Retrieve details for a specific user by ID.

    :param user_id: The ID of the user to retrieve.
    :return: Message with user details.
    """
    return {"message": f"Details of user {user_id}"}

@router.post("/avatar")
async def update_avatar(file: UploadFile = File(...), db: AsyncSession = Depends(get_db)):
    """
    Upload and update a user's avatar image.

    :param file: Upload image file.
    :param db: Async database session
    :return: URL of the uploaded avatar image.
    """
    url = upload_avatar(file.file)
    return {"avatar_url": url}