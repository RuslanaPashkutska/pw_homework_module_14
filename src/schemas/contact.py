from pydantic import BaseModel, EmailStr
from datetime import date
from typing import Optional


class ContactBase(BaseModel):
    """
    Shared base model for contact data.

    Attributes:
        first_name (str): The first name of the contact.
        last_name (str): The last name of the contact.
        email (EmailStr): The email address of the contact.
        phone_number (str): The phone number of the contact.
        phone_number (str): The phone number of the contact.
        birthday (date): The contact's date of birth.
        extra_info (Optional[str]): Any additional information about the contact.
    """
    first_name: str
    last_name: str
    email: EmailStr
    phone: str
    birthday: date
    extra_info: Optional[str] = None


class ContactCreate(ContactBase):
    """
    Schema for creating a new contact.
    Inherits all fields from ContactBase.
    """
    pass


class ContactUpdate(ContactBase):
    """
    Schema for updating an existing contact.
    Inherits all fields from ContactBase.
    """
    pass


class ContactResponse(ContactBase):
    """
    Schema for returning contact data in responses.

    Attributes:
        id (int): Unique identifier for the contact.
        user_id (int): ID of the user who owns the contact.
    """
    id: int
    user_id: int

    class Config:
        from_attributes = True