import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl
dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../.env'))


class Settings(BaseSettings):
    database_url: str
    database_test_url: str = "sqlite+aiosqlite:///./test_db.sqlite3"



    secret_key: str
    refresh_secret_key: str
    JWT_ALGORITHM: str = "HS256"
    algorithm: str = "HS256"
    access_token_minutes: int = 30
    refresh_token_expire_days: int = 7
    debug: bool = False
    debug_mode: bool = False

    cloudinary_name: str
    cloudinary_api_key: str
    cloudinary_api_secret: str

    mail_username: str
    mail_password: str
    mail_from: str
    mail_port: int
    mail_server: str
    mail_starttls: bool
    mail_ssl: bool

    redis_host: str
    redis_port: int = 6379

    base_url: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()

print("DB URL:", settings.database_url)
print("Debug mode:", settings.debug)
print("Cloudinary Name:", settings.cloudinary_name)
print("Mail Server:", settings.mail_server)
print("Redis Host:", settings.redis_host)
print("Ruta .env usada:", dotenv_path)