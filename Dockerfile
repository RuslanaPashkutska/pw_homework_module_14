FROM python:3.13-slim
LABEL authors="ruslana"

WORKDIR /app
COPY pyproject.toml poetry.lock /app/

RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-root

COPY src /app/src



EXPOSE 8000

CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]