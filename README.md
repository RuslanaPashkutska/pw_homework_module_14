# **Contacts API**

Backend REST API for managing users and their personal contacts, built with FastAPI.

This project implements a full authentication and authorization flow using OAuth2 Password Flow with JWT, user-scoped resources, async database access, caching, rate limiting, email verification, and cloud storage for avatars.

---

## 🚀 Features

### 🔐 Authentication & Security
* User registration and login
* Email verification flow
* OAuth2 Password Flow
* JWT access and refresh tokens
* Protected endpoints using `Depends(get_current_user)`
* Rate limiting with Redis

### 📇 Contacts Management
* Create, read, update, delete contacts (CRUD)
* Contacts are scoped to the authenticated user
* Search contacts by name or email
* Get upcoming birthdays

### 👤 Users
* Get current user profile
* Upload user avatar to Cloudinary

---

## 🛠 Tech Stack

* FastAPI
* Async SQLAlchemy
* PostgreSQL
* Redis (rate limiting)
* Cloudinary (avatar storage)
* JWT / OAuth2
* Pydantic
* Alembic (migrations)
* Poetry (dependency management)
* Pytest / Unittest (tests)

---

## 📂 Project Structure

```codigo
src/
├── auth/          # Authentication logic
├── routes/        # API routes (auth, contacts, users)
├── database/      # DB session and models
├── repository/    # Database access layer
├── schemas/       # Pydantic schemas
├── services/      # Business logic
├── conf/          # Settings and config
├── cache/         # Redis client
└── main.py        # Application entry point

```
---

## ⚙️ Environment Variables

Create a `.env` file based on `.env.example`:

```env
DATABASE_URL=postgresql+psycopg://user:password@localhost:5432/contacts_db

CLOUDINARY_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_api_key
CLOUDINARY_API_SECRET=your_api_secret

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

SECRET_KEY=your-secret-key
REFRESH_SECRET_KEY=your-refresh-secret
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_FROM=your_email@gmail.com
MAIL_PORT=587
MAIL_SERVER=smtp.gmail.com
MAIL_STARTTLS=True
MAIL_SSL=False

BASE_URL=http://localhost:8000

FRONTEND_BASE_URL=http://localhost:3000
```
---

## ▶️ Run the Project

### 1️⃣ Install dependencies
```bash
  poetry install
```
### 2️⃣ Run database migrations
```bash
  alembic upgrade head
```
### 3️⃣ Start the server
```bash
  poetry run uvicorn src.main:app --reload
```
### The API will be available at:
```codigo
http://127.0.0.1:8000
```
### Swagger UI:
```codigo
http://127.0.0.1:8000/docs
```
---
## 🔐 Authentication Flow

1. Register a new user (POST /auth/register)


2. Verify email via link sent by email (GET /auth/verify_email/{token})


3. Login using OAuth2 (POST /auth/login)


4. In Swagger UI, click Authorize and enter:

   * username → email

   * password → user password

5. Access protected endpoints
---
## 📌 Contacts Endpoints (Protected)

* GET /contacts/ — list contacts

* POST /contacts/ — create contact

* GET /contacts/{id} — get contact by id

* PUT /contacts/{id} — update contact

* DELETE /contacts/{id} — delete contact

* GET /contacts/search/?query= — search contacts

* GET /contacts/birthdays/upcoming — upcoming birthdays
---
## 🧪 Tests

Run tests with:
```bash
  pytest --cov=src
```