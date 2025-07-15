import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import delete
from unittest.mock import patch, AsyncMock
import redis.asyncio as aioredis

from src.main import app
from src.database.db import get_db, Base
from src.database.models import User
from src.auth.auth import get_password_hash, create_access_token
from fastapi_limiter import FastAPILimiter
from src.conf.config import settings

TEST_DATABASE_URL = settings.database_test_url
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
TestSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine, # Usar el engine de test aquí
    class_=AsyncSession,
    expire_on_commit=False
)

@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="session")
async def redis_client_fixture():
    """
    Provides a Redis client for FastAPILimiter, initialized once per test session.
    """

    client = aioredis.from_url("redis://localhost", encoding="utf8", decode_responses=True)
    await FastAPILimiter.init(client)
    yield client
    await FastAPILimiter.close()
    await client.close()


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    async with TestSessionLocal() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()



@pytest_asyncio.fixture
async def test_client(db_session: AsyncSession, mock_limiter_components):
    async def override_get_db_for_test_client():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db_for_test_client

    with patch.object(FastAPILimiter, 'init', new_callable=AsyncMock), \
            patch.object(FastAPILimiter, 'redis', new=mock_limiter_components["redis_client"]), \
            patch.object(FastAPILimiter, 'identifier', new=mock_limiter_components["identifier"]), \
            patch.object(FastAPILimiter, 'http_callback', new=mock_limiter_components["http_callback"]), \
            patch.object(FastAPILimiter, 'lua_sha', new=mock_limiter_components["lua_sha"]):

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                try:
                    yield client
                finally:
                    app.dependency_overrides.pop(get_db, None)

@pytest_asyncio.fixture()
async def session(db_session: AsyncSession):
    yield db_session


@pytest_asyncio.fixture
async def test_user(session: AsyncSession):
    hashed_password = get_password_hash("password123")
    user = User(email="testuser@example.com", hashed_password=hashed_password, is_verified=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user



@pytest_asyncio.fixture(autouse=True)
async def clean_users(db_session):
    for table in reversed(Base.metadata.sorted_tables):
        await db_session.execute(delete(table))
    await db_session.commit()

@pytest_asyncio.fixture
async def token(test_user, session: AsyncSession):
    user = test_user
    return create_access_token(data={"sub": user.email})

@pytest_asyncio.fixture(scope="session")
async def mock_limiter_components():
    mock_redis_client = AsyncMock(spec=aioredis.Redis)
    mock_redis_client.evalsha = AsyncMock(return_value=0)

    mock_identifier = AsyncMock(return_value="test_client_id")
    mock_http_callback = AsyncMock(return_value=None)
    mock_lua_sha = "mock_lua_sha"

    return {
        "redis_client": mock_redis_client,
        "identifier": mock_identifier,
        "http_callback": mock_http_callback,
        "lua_sha": mock_lua_sha
    }

