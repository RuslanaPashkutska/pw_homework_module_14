
FROM python:3.13-slim


ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app


RUN pip install poetry


COPY pyproject.toml poetry.lock /app/


RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root


COPY . /app/


EXPOSE 8000


CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]