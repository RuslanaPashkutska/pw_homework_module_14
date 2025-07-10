
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import or_, select
from datetime import date, timedelta
from src.database import models
from src.schemas.contact import ContactCreate, ContactUpdate

__all__ = [
    "create_contact", "get_contact", "get_contacts", "update_contact",
    "delete_contact", "search_contacts", "get_upcoming_birthdays"
]


async def create_contact(db: AsyncSession, contact: ContactCreate, user_id: int):
    """
    Create a new contact in the database.

    :param db: Async SQLAlchemy session.
    :param contact: ContactCreate schema with contact data.
    :param user_id: ID of the user who owns the contact.
    :return: The created contact object.
    """
    db_contact = models.Contact(**contact.model_dump(), owner_id=user_id)
    db.add(db_contact)
    await db.commit()
    await db.refresh(db_contact)
    return db_contact



async def get_contact(db: AsyncSession, contact_id: int, user_id: int):
    """
    Retrieve a contact by its ID and owner.

    :param db: Async SQLAchemy session.
    :param contact_id: ID of the contact to retrieve.
    :param user_id: ID of the user who owns the contact.
    :return: Contact object if found, otherwise None.
    """
    result = await db.execute(
        select(models.Contact).filter(
            models.Contact.id == contact_id,
            models.Contact.owner_id == user_id
        )
    )
    return result.scalar_one_or_none()


async def get_contacts(db: AsyncSession, user_id: int, skip: int = 0, limit: int =100):
    """
    Retrieve a list of contacts for the specified user.

    :param db: Async SQLAchemy session.
    :param user_id: ID of the user who owns the contact.
    :param skip: Number of records to skip for pagination.
    :param limit: Maximum number of records to return.
    :return: List of contact objects.
    """
    result = await db.execute(
        select(models.Contact).filter(models.Contact.owner_id == user_id).offset(skip).limit(limit)
    )
    return result.scalars().all()


async def update_contact(db: AsyncSession, contact_id: int, updated: ContactUpdate, user_id: int):
    """
    Update a contact with new data.

    :param db: Async SQLAlchemy session.
    :param contact_id: ID of the contact to update.
    :param updated: ContactUpdate schema with fields to update.
    :param user_id: ID of the user who owns the contact.
    :return: The updated contact object, or None if not found.
    """
    contact = await get_contact(db, contact_id, user_id)
    if contact:
        for key, value in updated.model_dump(exclude_unset=True).items():
            setattr(contact, key, value)
        await db.commit()
        await db.refresh(contact)
    return contact

async def delete_contact(db: AsyncSession, contact_id: int, user_id: int):
    """
    Delete a contact by its ID and owner.

    :param db: Async SQLAlchemy session.
    :param contact_id: ID of the contact to delete.
    :param user_id: ID of the user who owns the contact.
    :return: The delete contact object, or None if not found.
    """
    contact = await get_contact(db, contact_id, user_id)
    if contact:
        await db.delete(contact)
        await db.commit()
    return contact

async def search_contacts(db: AsyncSession, query: str, user_id: int):
    """
    Search for contacts by first name, last name, or email.

    :param db: Async SQLAlchemy session.
    :param query: Search query string.
    :param user_id: ID of the user who owns the contacts.
    :return: List of matching contact objects.
    """
    result = await db.execute(
        select(models.Contact).filter(
            models.Contact.owner_id == user_id,
            or_(
                models.Contact.first_name.ilike(f"%{query}%"),
                models.Contact.last_name.ilike(f"%{query}%"),
                models.Contact.email.ilike(f"%{query}%")
            )
        )
    )
    return result.scalars().all()

async def get_upcoming_birthdays(db: AsyncSession, user_id: int):
    """
    Retrieve contacts whose birthdays are within the next 7 days.

    :param db: Async SQLAlchemy session.
    :param user_id: ID of the user who owns the contacts.
    :return: List of contact objects with upcoming birthdays.
    """
    today = date.today()
    next_week = today + timedelta(days=7)
    result = await db.execute(
        select(models.Contact).filter(
            models.Contact.owner_id == user_id,
            models.Contact.birthday.between(today, next_week)
        )
    )
    return result.scalars().all()
