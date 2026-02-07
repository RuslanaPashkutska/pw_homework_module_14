from pydantic import BaseModel, EmailStr, ConfigDict
from datetime import datetime
from typing import Optional


class UserBase(BaseModel):
    """
    Base schema for user data.

    Attributes:
        email (EmailStr): The email address of the user.
    """
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class UserCreate(UserBase):
    """
    Schema for creating a new user.

     Attributes:
        password (str): The password for the new user.
    """
    password: str

class UserLogin(UserBase):
    """
    Schema for user login.

    Attributes:
        password (str): The user's password for authentication.
    """
    password: str

class UserDataResponse(UserBase):
    id: int
    is_verified: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)



class UserResponse(BaseModel):
    """
    Schema for returning user data in responses.

    Attributes:
        id (int): The unique identifier of the user.
        created_at (Optional[date]): The date the user was created.
    """
    user: UserDataResponse
    detail: str
    model_config = ConfigDict(from_attributes=True)
    verification_token: Optional[str] = None


class Token(BaseModel):
    """
    Schema for authentication tokens.

    Attributes:
        access_token (str): The JWT access token.
        refresh_token (str): The JWT refresh token.
        token_type (str): The type of the token (default: "bearer").
    """
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """
    Schema for token payload data.

    Attributes:
        email (Optional[str]): The email extracted from the token.
    """
    email: Optional[str] = None

class RequestPasswordReset(BaseModel):
    """
    Schema for requesting a password reset.

    Attributes:
        email (EmailStr): The email address to send the reset link to.
    """
    email: EmailStr

class ResetPassword(BaseModel):
    """
    Schema for resetting the password.

    Attributes:
        token (str): The password reset token.
        new_password (str): The new password to set.
    """
    token: str
    new_password: str