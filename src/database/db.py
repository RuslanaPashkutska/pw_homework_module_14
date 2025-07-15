import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
from src.conf.config import settings


engine = create_async_engine(settings.database_url, echo=False)

AsyncSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)
Base = declarative_base()

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get an asynchronous database session for production.
    This will be overridden in testing environments.
    """
    db = AsyncSessionLocal()
    try:
        yield db
    finally:
        await db.close()
