from fastapi import APIRouter, Depends, HTTPException, status, Response
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from src.schemas.contact import ContactCreate, ContactResponse, ContactUpdate
from src.database.db import get_db
from src.auth.auth import get_current_user
from src.database.models import User, Contact as ContactModel
from src.repository import contacts as repository_contacts
from fastapi_limiter.depends import RateLimiter
from src.cache.redis_client import redis_client


router = APIRouter(prefix="/contacts", tags=["contacts"])

@router.get("/", response_model=List[ContactResponse])
async def get_contacts(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Get all contacts for the current authenticated user.

    :param current_user: Authenticated user.
    :param db: Database session.
    :return: List of contact objects.
    """
    contacts = await repository_contacts.get_contacts(db, current_user.id)
    return contacts

@router.post("/", response_model=ContactResponse, status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=5, seconds=60))])
async def create_contact(contact: ContactCreate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Create a new contact for the authenticated user.

    Rate limited to 5 requests per 60 seconds.

    :param contact: ContactCreate schema.
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: The newly created contact.
    """
    new_contact = ContactModel(
        first_name=contact.first_name,
        last_name=contact.last_name,
        email=contact.email,
        phone=contact.phone,
        birthday=contact.birthday,
        extra_info=contact.extra_info,
        owner_id=current_user.id
    )
    db.add(new_contact)
    await db.commit()
    await db.refresh(new_contact)
    return new_contact

@router.get("/{contact_id}", response_model=ContactResponse)
async def get_contact_by_id(contact_id: int, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Retrieve a specific contact by ID.
    :param contact_id: ID of the contact.
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: Contact object if found.
    """
    contact = await repository_contacts.get_contact(db, contact_id, current_user.id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return contact

@router.put("/{contact_id}", response_model=ContactResponse)
async def update_contact(contact_id: int, updated_contact: ContactUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Update an existing contact by ID.

    :param contact_id: ID of the contact to update.
    :param updated_contact: Updated contact data.
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: Update contact object.
    """
    contact = await repository_contacts.update_contact(db, contact_id, updated_contact, current_user.id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")
    return contact

@router.delete("/{contact_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_contact(contact_id: int, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Delete a contact ID.

    :param contact_id: ID of the contact to delete.
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: 204 No Content on successful deletion.
    """
    contact = await repository_contacts.delete_contact(db, contact_id, current_user.id)
    if contact is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Contact not found")

@router.get("/search/", response_model=List[ContactResponse])
async def search_contacts(query: Optional[str] = None, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Search contacts by name, email, or other fields.

    :param query: Search string (optional)
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: List of matching contacts.
    """
    if query is None or not query.strip():
        return await repository_contacts.get_contacts(db, current_user.id)
    contacts = await repository_contacts.search_contacts(db, query, current_user.id)
    return contacts

@router.get("/birthdays/upcoming", response_model=List[ContactResponse])
async def get_upcoming_birthdays(current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """
    Get contacts with upcoming birthdays within the next 7 days.
    :param current_user: Authenticated user.
    :param db: Database session.
    :return: List of contacts with upcoming birthdays.
    """
    birthdays = await repository_contacts.get_upcoming_birthdays(db, current_user.id)
    return birthdays
