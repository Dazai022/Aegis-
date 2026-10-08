FROM python:3.12-slim
WORKDIR /app
RUN adduser --disabled-password --gecos "" aegis
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[dev]"
COPY . .
RUN chown -R aegis:aegis /app
USER aegis
EXPOSE 8000
ENTRYPOINT ["sh", "-c", "python -m alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
