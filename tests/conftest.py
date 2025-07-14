import pytest_asyncio
import redis.asyncio as redis
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import delete

from src.main import app
from src.database.db import get_db, Base, engine_test
from src.database.models import User
from src.auth.auth import get_password_hash, create_access_token
from fastapi_limiter import FastAPILimiter


TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

engine_test = create_async_engine(TEST_DATABASE_URL, echo=False, poolclass=NullPool)
TestingSessionLocal = sessionmaker(bind=engine_test, class_=AsyncSession, expire_on_commit=False)

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture(autouse=True)
async def clean_users(session):
    await session.execute(delete(User))
    await session.commit()

@pytest_asyncio.fixture(scope="session", autouse=True)
async def prepare_database():
    async with engine_test.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield

@pytest_asyncio.fixture
async def session() -> AsyncSession:
    async with engine_test.connect() as conn:
        async  with AsyncSession(bind=conn, expire_on_commit=False) as session:
            yield session

@pytest_asyncio.fixture
async def test_client(prepare_database):
    redis_client = redis.from_url("redis://localhost", encoding="utf8", decode_responses=True)
    await FastAPILimiter.init(redis_client)

    async with engine_test.connect() as conn:
        async with AsyncSession(bind=conn, expire_on_commit=False) as session:

            async def override_get_db():
                yield  session

            app.dependency_overrides[get_db] = override_get_db

            await session.execute(delete(User))
            await session.commit()

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                yield client

        app.dependency_overrides.pop(get_db, None)

@pytest_asyncio.fixture
async def test_user(session):
    hashed_password = get_password_hash("password123")
    user = User(email="testuser@example.com", hashed_password=hashed_password, is_verified=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user

@pytest_asyncio.fixture
async def token(test_user, session):
    user = test_user
    return create_access_token(data={"sub": user.email})



