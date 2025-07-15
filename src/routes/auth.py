from fastapi import APIRouter, Depends, HTTPException, status, Form
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from src.schemas.user import RequestPasswordReset, ResetPassword, Token, UserLogin, UserCreate, UserResponse
from src.repository import users as repository_users
from src.auth.auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_email_token,
    create_password_reset_token_and_save,
    reset_password as auth_reset_password_logic,
    create_email_verification_token_and_save
)
from src.services.email import send_email
from src.database.db import get_db
from src.conf.config import settings
from datetime import datetime, timezone


router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user.
    - Hashed the password.
    - Saves the user to the database.
    - Sends a verification email with a token.

    :param user: UserCreate schema containing user registration data.
    :param db: Database session.
    :return: The newly registered user.
    """
    existing_user = await repository_users.get_user_by_email(db, user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")
    hashed_password = get_password_hash(user.password)
    new_user = await repository_users.create_user(user=user, hashed_password=hashed_password, db=db)

    verification_token = await create_email_verification_token_and_save(new_user.email, db)

    try:
        await send_email(new_user.email, new_user.email, verification_token, "verify_email")
        detail_message = "User successfully registered. Check your email for verification."
    except Exception as e:
        print(f"DEBUG_TEST: Fallo al enviar email de verificación a {new_user.email}: {e}")
        print(f"ATENCIÓN: Fallo al enviar email de verificación a {new_user.email}: {e}")
        detail_message = "User successfully registered, but failed to send verification email. Please contact support."

    return UserResponse(user=new_user, detail=detail_message)


@router.get("/verify_email/{token}")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    """
    Verify a user's email address using the token.

    :param token: Verification token from email link.
    :param db: Database session.
    :return: Success message if the token is valid.
    """
    user = await verify_email_token(token, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")
    return {"message": "Email successfully verified"}

@router.post("/login", response_model=Token)
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Authenticate user and return access and refresh tokens.

    :param user: UserLogin schema with email and password.
    :param db: Database session.
    :return: JWT access and refresh tokens.
    """
    db_user = await repository_users.get_user_by_email(db, user.email)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not db_user.is_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Email not verified. Please check your inbox.")
    access_token = create_access_token(data={"sub": db_user.email})
    refresh_token = create_refresh_token(data={"sub": db_user.email})
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post("/request_password_reset", status_code=status.HTTP_200_OK)
async def request_password_reset(body: RequestPasswordReset, db: AsyncSession = Depends(get_db)):
    """
    Send a password reset link to the user's email if they exist.

    :param body: RequestPasswordReset schema with user's email
    :param db: Database session.
    :return: Message indicating reset link was sent is user exists.
    """
    try:
        user = await repository_users.get_user_by_email(db, body.email)
        if user:
            token = await create_password_reset_token_and_save(body.email, db)
            await send_email(user.email, user.email, token, "reset_password")
    except Exception as e:
        print(f"ATENCIÓN: Fallo al enviar email de reseteo a {body.email}: {e}")
    return {"message": "If a user with that email exists, a password reset link has been sent."}


@router.post("/reset_password", status_code=status.HTTP_200_OK)
async def reset_password_json_endpoint(body: ResetPassword, db: AsyncSession = Depends(get_db)):
    try:
        user = await auth_reset_password_logic(body.token, body.new_password, db)
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
    except HTTPException as e:
        raise e
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"An unexpected error occurred: {e}")
    print("DEBUG: Línea de retorno de reset_password_json_endpoint alcanzada.")
    return {"message": "Password has been reset successfully"}


@router.post("/reset-password-form", status_code=status.HTTP_200_OK)
async def reset_password_form_endpoint(token: str = Form(...), new_password: str = Form(...),
                                  db: AsyncSession = Depends(get_db)):
    print(
        f"DEBUG src/routes/auth.py reset_password_form_endpoint: db received in route: {type(db)} - {db}")
    try:
        user = await auth_reset_password_logic(token, new_password, db)
        if user is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")
    except HTTPException as e:
        raise e
    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired token")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail=f"An unexpected error occurred: {e}")
    print("DEBUG: Línea de retorno de reset_password_form_endpoint alcanzada.")
    return {"message": "Password has been reset successfully"}