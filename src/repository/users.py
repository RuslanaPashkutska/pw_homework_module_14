from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from src.database import models
from src.schemas.user import UserCreate


async def get_user_by_email(db: AsyncSession, email: str):
    """
    Retrieve a user from the database by their email address.

    :param db: Async SQLAlchemy session.
    :param email: Email address of the user.
    :return: User object if found, otherwise None.
    """
    result = await db.execute(
        select(models.User).filter(models.User.email == email)
    )
    return result.scalar_one_or_none()

async def get_user_by_id(db: AsyncSession, user_id: int):
    """
    Retrieve a user from the database by their ID.
    :param db: Async SQLAlchemy session.
    :param user_id: ID of the user.
    :return: User object if found, otherwise None.
    """
    result = await db.execute(
        select(models.User).filter(models.User.id == user_id)
    )
    return result.scalar_one_or_none()


async def create_user(db: AsyncSession, user: UserCreate, hashed_password: str):
    """
    Create a new user in the database.
    :param db: Async SQLAlchemy session.
    :param user: UserCreate schema containing user input data.
    :param hashed_password: Hashed version of the user's password.
    :return: The newly created user object.
    """
    db_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    return db_user

async def update_user_is_verified(db: AsyncSession, user_id: int, is_verified: bool) -> Optional[models.User]:
    """
    Update the user's verification status.

    :param db: Async SQLAlchemy session.
    :param user_id: ID of the user.
    :param is_verified: Boolean indicating whether the user is verified.
    :return: Update user object if found, otherwise None.
    """
    user = await get_user_by_id(db, user_id)
    if user:
        user.is_verified = is_verified
        await db.commit()
        await db.refresh(user)
    return user


async def update_user_password(db: AsyncSession, user_id: int, new_hashed_password: str) -> Optional[models.User]:
    """
    Update the user's password.

    :param db: Async SQLAlchemy session.
    :param user_id: ID of the user.
    :param new_hashed_password: New hashed password to store.
    :return: Updated user object if found, otherwise None.
    """
    user = await get_user_by_id(db, user_id)
    if user:
        user.hashed_password = new_hashed_password
        await db.commit()
        await db.refresh(user)
    return user

async def update_user_avatar(db: AsyncSession, user_id: int, avatar_url: str) -> Optional[models.User]:
    """
    Update the user's avatar URL.

    :param db: Async SQLAlchemy session.
    :param user_id: ID of the user.
    :param avatar_url: URL of the new avatar image.
    :return: Update user object if found, otherwise None.
    """
    user = await  get_user_by_id(db, user_id)
    if user:
        user.avatar = avatar_url
        await db.commit()
        await db.refresh(user)
    return user