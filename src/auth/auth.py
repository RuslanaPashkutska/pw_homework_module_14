from datetime import datetime, timedelta
from typing import Optional
import uuid
from jose import JWTError, jwt
from passlib.context import CryptContext

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.db import get_db
from src.database.models import User, VerificationToken
from src.schemas.user import TokenData
from src.repository import users as repository_users
from src.repository import auth as repository_auth
from src.conf.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def get_password_hash(password:str) -> str:
    """
    Hashed the given plain password using bcrypt.

    :param password: Plain text password to hash.
    :return: Hashed password as a string.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password:str) -> bool:
    """
    Verifies a plain password against a hashed password.

    :param plain_password: The plain text password.
    :param hashed_password: The hashed password.
    :return: True if match, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT access token.

    :param data: Payload data to encode.
    :param expires_delta: Opcional expiration time.
    :return: Encoded JWT token as a string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT refresh token.

    :param data: Payload data to encode.
    :param expires_delta: Opcional expiration time.
    :return: Encoded JWT refresh token as a string.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=30))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.refresh_secret_key, algorithm=settings.algorithm)
    return encoded_jwt

async def get_current_user(token:str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    """
    Retrieves the current user from the JWT token.

    :param token: JWT token from request header.
    :param db: Async database session.
    :return: User instance if valid token.
    :raises HTTPException: If token is invalid or user not verified.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = await repository_users.get_user_by_email(db, token_data.email)
    if user is None:
        raise credentials_exception
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def create_email_verification_token_and_save(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates and encodes an email verification JWT token.

    :param data: Data to include in the token.
    :param expires_delta: Optional expiration time.
    :return: Encoded verification token.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(days=14))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.refresh_secret_key, algorithm=settings.algorithm)


def create_email_verification_token(user_id: int) -> str:
    """
    Creates a raw UUID token string for email verification.

    :param user_id: ID of the user.
    :return: UUID token string.
    """
    token = str(uuid.uuid4())
    return token

async def save_verification_token(user_id: int, token: str, token_type:str, db:AsyncSession) -> None:
    """
    Saves a verification token to the database.

    :param user_id: ID of the user.
    :param token: The token string.
    :param token_type: The type of token (e.g. 'email_verification').
    :param db: Async database session.
    """
    expires_at = datetime.utcnow() + timedelta(hours=2)
    verification_token_db = VerificationToken(
        user_id=user_id,
        token=token,
        token_type=token_type,
        expires_at=expires_at
    )
    await repository_auth.create_verification_token(verification_token_db, db)

async def verify_email_token(token: str, db: AsyncSession) -> Optional[User]:
    """
    Verifies the given email token and marks user as verified.

    :param token: Token string to verify.
    :param db: Async database session.
    :return: User if token valid and verification successful, else None.
    """
    verification_token = await repository_auth.get_verification_token(token, "email_verification", db)

    if verification_token is None or verification_token.expires_at < datetime.utcnow():
        return None

    user = await repository_users.get_user_by_id(verification_token.user_id, db)
    if user:
        user.is_verified = True
        await repository_users.update_user(user, db)
        await repository_auth.delete_verification_token(verification_token.id, db)
    return user


async def create_password_reset_token_and_save(user_email: str, db: AsyncSession) -> Optional[str]:
    """
    Generates and saves a password reset token.

    :param user_email: Email of the user requesting reset.
    :param db: Async database session.
    :return: The reset token string, or None if user not found.
    """
    user = await repository_users.get_user_by_email(user_email, db)
    if not user:
        return None

    token = str(uuid.uuid4())
    await save_verification_token(user.id, token, "password_reset", db)
    return token

async def reset_password(token: str, new_password: str, db: AsyncSession) -> Optional[User]:
    """
    Reset user's password using a valid reset token.

    :param token: Password reset token.
    :param new_password: New password to set.
    :param db: Async database session.
    :return: Update user or None if token invalid.
    """
    reset_token = await repository_auth.get_verification_token(token, "password_reset", db)

    if reset_token is None or reset_token.expires_at < datetime.utcnow():
        return None

    user = await repository_users.get_user_by_id(reset_token.user_id, db)
    if user:
        hashed_new_password = get_password_hash(new_password)
        await repository_users.update_user_password(user.id, hashed_new_password, db)
        await repository_auth.delete_verification_token(reset_token.id, db)
    return user