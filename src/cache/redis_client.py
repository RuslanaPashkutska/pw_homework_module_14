import redis.asyncio as redis
from src.conf.config import settings

redis_client = redis.from_url(
    f"redis://{settings.redis_host}:{settings.redis_port}",
    encoding="utf-8",
    decode_responses=True
)