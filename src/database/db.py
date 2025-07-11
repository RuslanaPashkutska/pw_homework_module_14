import os
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base

from src.conf.config import settings


engine = create_async_engine(settings.database_url)

if os.getenv("TESTING"):
    from sqlalchemy.pool import NullPool
    TEST_DATABASE_URL = "sqlite+aiosqlite:///./test_db.sqlite3"
    engine_test = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
else:
    engine_test = None


AsyncSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

AsyncSessionTestLocal = None
if engine_test:
    AsyncSessionTestLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine_test,
        class_=AsyncSession,
        expire_on_commit=False
    )

Base = declarative_base()

async def get_db():
    db = AsyncSessionLocal()
    try:
        yield db
    finally:
        await db.close()