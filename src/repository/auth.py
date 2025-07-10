from sqlalchemy.ext.asyncio import  AsyncSession
from sqlalchemy import select, delete
from src.database import models
from typing import Optional

async def create_verification_token(token_db: models.VerificationToken, db:AsyncSession) -> models.VerificationToken:
    """
    Add new verification token to the database.

    :param token_db: VerificationToken model instance to be stored.
    :param db: Async SQLAlchemy session.
    :return: The newly created VerificationToken object.
    """
    db.add(token_db)
    await db.commit()
    await db.refresh(token_db)
    return token_db

async def get_verification_token(token: str, token_type, db: AsyncSession) -> Optional[models.VerificationToken]:
    """
    Retrieve a verification token by its value and type.
    :param token: The token string to look for.
    :param token_type: The type of the token (e.g. verification, password_reset).
    :param db: Async SQLAlchemy session.
    :return: Matching VerificationToken object if found, otherwise None.
    """
    result = await db.execute(
        select(models.VerificationToken).filter(
            models.VerificationToken.token == token,
            models.VerificationToken.token_type == token_type
        )
    )
    return result.scalar_one_or_none()

async def delete_verification_token(token_id: int, db: AsyncSession) -> None:
    """
    Delete a verification token from the database by its ID.

    :param token_id: ID of the token to delete.
    :param db: Async SQLAlchemy session.
    :return: None
    """
    stmt = delete(models.VerificationToken).where(models.VerificationToken.id == token_id)
    await db.execute(stmt)
    await db.commit()