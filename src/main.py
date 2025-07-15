from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi_limiter import FastAPILimiter
import cloudinary
import cloudinary.uploader
import redis.asyncio as redis

from src.conf.config import settings

from src.routes import auth, contact, users
from src.cache.redis_client import redis_client as default_redis_client
from src.database.db import Base, engine

app = FastAPI(
    title="Contacts API",
    description="API for managing contacts, users, authentication, and more.",
    version="0.1.0",
)

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(contact.router)
app.include_router(users.router)


@app.on_event("startup")
async def startup_event(redis_client_instance: redis.Redis = default_redis_client):
    """
        Startup event handler to initialize services such as:
        - Redis rate limiter (FastAPILimiter)
        - Cloudinary configuration
        - Database table creation via SQLAlchemy

        Raises:
            Exception: If Redis or database setup fails.
        """
    print("Starting up application...")

    try:
        await FastAPILimiter.init(redis_client_instance)
        print("FastAPILimiter initialized with Redis.")
    except Exception as e:
        print(f"Error initializing FastAPILimiter: {e}")


    cloudinary.config(
        cloud_name=settings.cloudinary_name,
        api_key=settings.cloudinary_api_key,
        api_secret=settings.cloudinary_api_secret,
        secure=True
    )
    print("Cloudinary configured.")


    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        print("Database tables created/checked.")
    print("Application startup complete.")

@app.get("/")
async def read_root():
    """
        Root endpoint for the Contacts API.

        Returns:
            dict: A welcome message.
        """
    return {"message": "Welcome to the Contacts API!"}