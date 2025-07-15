from typing import Optional
import uuid
from jose import JWTError, jwt
from passlib.context import CryptContext

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta, timezone
from src.database.db import get_db
from src.database.models import User, VerificationToken
from src.schemas.user import TokenData
from src.repository import users as repository_users
from src.repository import auth as repository_auth
from src.conf.config import settings


ALGORITHM = "HS256"
SECRET_KEY = "your-secret-key"

def make_aware(dt: datetime) -> datetime:
    """
    Ensures a datetime object has timezone information, defaulting to UTC if naive.

    :param dt: The datetime object.
    :return: Timezone-aware datetime object.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_password_hash(password: str) -> str:
    """
    Hashes the given plain password using bcrypt.

    :param password: Plain text password to hash.
    :return: Hashed password as a string.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
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
    :param expires_delta: Optional expiration time.
    :return: Encoded JWT token as a string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=7))
    to_encode.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a JWT refresh token.

    :param data: Payload data to encode.
    :param expires_delta: Optional expiration time.
    :return: Encoded JWT refresh token as a string.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(days=30))
    to_encode.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(to_encode, settings.refresh_secret_key, algorithm=settings.algorithm)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
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
    user = await repository_users.get_user_by_email(db, email)
    if user is None:
        raise credentials_exception
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


async def create_email_verification_token_and_save(email: str, db: AsyncSession,
                                                   expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates and encodes an email verification JWT token.

    :param email: User's email to include in the token.
    :param db: Async database session.
    :param expires_delta: Optional expiration time.
    :return: Encoded verification token.
    :raises HTTPException: If user not found.
    """
    user = await repository_users.get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    data = {"sub": email, "type": "email_verification", "jti": str(uuid.uuid4())}
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=14)

    to_encode.update({"exp": expire.timestamp()})

    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

    await save_verification_token(user.id, encoded_jwt, "email_verification", db)

    return encoded_jwt


def create_email_verification_token(user_id: int) -> str:
    """
    Creates a raw UUID token string for email verification.
    Note: This is likely a legacy or auxiliary function, as JWTs are used for actual verification.

    :param user_id: ID of the user.
    :return: UUID token string.
    """
    return str(uuid.uuid4())


async def save_verification_token(user_id: int, token: str, token_type: str, db: AsyncSession) -> None:
    """
    Saves a verification token to the database.

    :param user_id: ID of the user.
    :param token: The token string.
    :param token_type: The type of token (e.g. 'email_verification').
    :param db: Async database session.
    """
    expires_at = datetime.now(timezone.utc) + timedelta(hours=2)
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
    :return: User if token valid and verification successful.
    :raises HTTPException: If token is invalid/expired, user not found, or email already verified.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired verification token"
    )
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "email_verification":
            raise credentials_exception


        verification_token_db = await repository_auth.get_verification_token(token, "email_verification", db)

        if verification_token_db is None or make_aware(verification_token_db.expires_at) < datetime.now(timezone.utc):
            raise credentials_exception

        user = await repository_users.get_user_by_email(db, email)
        if not user:
            raise credentials_exception

        if user.is_verified:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already verified")

        updated_user = await repository_users.update_user_is_verified(db, user.id, True)

        await repository_auth.delete_verification_token(verification_token_db.id, db)


        return updated_user

    except JWTError:
        raise credentials_exception


async def create_password_reset_token_and_save(email: str, db: AsyncSession,
                                               expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates and saves a password reset token.

    :param email: Email of the user requesting reset.
    :param db: Async database session.
    :return: The reset token string.
    :raises HTTPException: If user not found.
    """
    print(f"DEBUG create_password_reset_token_and_save: db received: {type(db)} - {db}")
    user = await repository_users.get_user_by_email(db, email)
    print(f"DEBUG create_password_reset_token_and_save: After get_user_by_email, db: {type(db)} - {db}")
    if user is None:

        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    data = {"sub": email, "type": "password_reset", "jti": str(uuid.uuid4())}
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire.timestamp()})

    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)

    print(f"DEBUG create_password_reset_token_and_save: Calling save_verification_token with db: {type(db)} - {db}")
    await save_verification_token(user.id, encoded_jwt, "password_reset", db)
    print(f"DEBUG create_password_reset_token_and_save: After save_verification_token, db: {type(db)} - {db}")

    return encoded_jwt


async def reset_password(token: str, new_password: str, db: AsyncSession) -> Optional[User]:
    print(f"DEBUG src/auth/auth.py reset_password: db received: {type(db)} - {db}")
    credentials_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid or expired reset token"
    )

    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        email: str = payload.get("sub")
        token_type: str = payload.get("type")

        if email is None or token_type != "password_reset":
            print("DEBUG src/auth/auth.py reset_password: Email is None or token_type is not password_reset.")
            raise credentials_exception

        print(f"DEBUG src/auth/auth.py reset_password: Calling get_verification_token with db: {type(db)} - {db}")
        reset_token_db = await repository_auth.get_verification_token(token, "password_reset", db)

        if reset_token_db is None:
            print("DEBUG src/auth/auth.py reset_password: Verification token not found in DB.")
            raise credentials_exception

        if make_aware(reset_token_db.expires_at) < datetime.now(timezone.utc):
            print("DEBUG src/auth/auth.py reset_password: Verification token expired.")
            raise credentials_exception

        print(f"DEBUG src/auth/auth.py reset_password: Calling get_user_by_email with db: {type(db)} - {db}")
        user = await repository_users.get_user_by_email(db, email)
        if not user:
            print(f"DEBUG src/auth/auth.py reset_password: User not found for email from token: {email}")
            raise credentials_exception

    except JWTError:
        print("DEBUG src/auth/auth.py reset_password: JWTError during token decode or validation.")
        raise credentials_exception
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"DEBUG src/auth/auth.py reset_password: Unexpected error during token validation: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred during token validation: {e}")



    hashed_new_password = get_password_hash(new_password)
    user.hashed_password = hashed_new_password

    print(f"DEBUG src/auth/auth.py reset_password: Before db.commit(), db: {type(db)} - {db}")
    await db.commit()
    print(f"DEBUG src/auth/auth.py reset_password: After db.commit(), db: {type(db)} - {db}")
    await db.refresh(user)
    print(f"DEBUG src/auth/auth.py reset_password: After db.refresh(), db: {type(db)} - {db}")

    print(f"DEBUG src/auth/auth.py reset_password: Calling delete_verification_token for token_id: {reset_token_db.id}")
    await repository_auth.delete_verification_token(reset_token_db.id, db)
    print(f"DEBUG src/auth/auth.py reset_password: After delete_verification_token, db: {type(db)} - {db}")

    return user