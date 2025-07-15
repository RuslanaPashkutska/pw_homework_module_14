import os
import pytest
from unittest.mock import patch, AsyncMock
from src.database.db import get_db
from unittest.mock import patch
from src.database import db


@pytest.mark.asyncio
@patch.dict(os.environ, {"TESTING": "1"})
async def test_get_db_yields_session_and_closes():
    mock_session = AsyncMock()
    mock_session.close = AsyncMock()

    with patch('src.database.db.AsyncSessionLocal', return_value=mock_session):
        db_generator = get_db()
        session = await anext(db_generator)

        assert session is mock_session
        mock_session.close.assert_not_awaited()

        await db_generator.aclose()
        mock_session.close.assert_awaited_once()