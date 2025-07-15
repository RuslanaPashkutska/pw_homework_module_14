import pytest
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch, AsyncMock, MagicMock

from src.main import app, startup_event
from src.database.db import Base


@pytest.fixture
def mock_redis_client_fixture():
    """Fixture to provide a mock Redis client."""
    return AsyncMock()

@pytest.mark.asyncio
async def test_read_root():
    """
    Tests the root endpoint of the FastAPI application.
    Ensures it returns a 200 OK status and the expected welcome message.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert response.json() == {"message": "Welcome to the Contacts API!"}

@pytest.mark.asyncio
@patch("src.main.FastAPILimiter.init", new_callable=AsyncMock)
@patch("src.main.cloudinary.config")
@patch("src.main.engine")
@patch("src.main.settings")
async def test_startup_event(
    mock_settings,
    mock_engine,
    mock_cloudinary_config,
    mock_limiter_init,
):
    """
    Tests the startup event handler of the FastAPI application.
    Mocks external dependencies to verify their initialization calls.
    """

    if not hasattr(mock_settings, 'cloudinary_name'):
        raise AssertionError(f"mock_settings is not the expected settings mock. It is: {repr(mock_settings)}")

    mock_settings.cloudinary_name = "test_cloud_name"
    mock_settings.cloudinary_api_key = "test_api_key"
    mock_settings.cloudinary_api_secret = "test_api_secret"

    if not hasattr(mock_engine, 'begin'):
        raise AssertionError(f"mock_engine is not the expected engine mock. It is: {repr(mock_engine)}")

    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock()

    mock_engine.begin.return_value.__aenter__.return_value = mock_conn
    mock_engine.begin.return_value.__aexit__.return_value = None

    await startup_event(redis_client_instance=mock_redis_client_fixture)

    if not isinstance(mock_limiter_init, AsyncMock):
        raise AssertionError(f"mock_limiter_init is not an AsyncMock. It is: {type(mock_limiter_init)}")

    mock_limiter_init.assert_awaited_once_with(mock_redis_client_fixture)

    if not isinstance(mock_cloudinary_config, MagicMock):
        raise AssertionError(f"mock_cloudinary_config is not a MagicMock. It is: {type(mock_cloudinary_config)}")

    mock_cloudinary_config.assert_called_once_with(
        cloud_name="test_cloud_name",
        api_key="test_api_key",
        api_secret="test_api_secret",
        secure=True
    )
    mock_engine.begin.assert_called_once()
    mock_conn.run_sync.assert_awaited_once_with(Base.metadata.create_all)

@pytest.mark.asyncio
@patch("src.main.FastAPILimiter.init", new_callable=AsyncMock)
@patch("src.main.cloudinary.config")
@patch("src.main.engine")
@patch("src.main.settings")
async def test_startup_event_redis_failure(
    mock_settings,
    mock_engine,
    mock_cloudinary_config,
    mock_limiter_init,
):
    """
    Test startup_event when Redis init fails to ensure exception handling is covered.
    """

    mock_limiter_init.side_effect = Exception("Redis init failed")

    mock_settings.cloudinary_name = "test"
    mock_settings.cloudinary_api_key = "key"
    mock_settings.cloudinary_api_secret = "secret"

    mock_conn = AsyncMock()
    mock_conn.run_sync = AsyncMock()
    mock_engine.begin.return_value.__aenter__.return_value = mock_conn
    mock_engine.begin.return_value.__aexit__.return_value = None

    mock_redis_client = AsyncMock()

    await startup_event(redis_client_instance=mock_redis_client)

    mock_cloudinary_config.assert_called_once_with(
        cloud_name="test",
        api_key="key",
        api_secret="secret",
        secure=True
    )

    mock_engine.begin.assert_called_once()
    mock_conn.run_sync.assert_awaited_once_with(Base.metadata.create_all)