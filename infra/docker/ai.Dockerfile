FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8001 \
    AI_APP_MODULE=app.main:app

WORKDIR /app

RUN groupadd --system codegate && useradd --system --gid codegate codegate
COPY . ./
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; \
    elif [ -f pyproject.toml ]; then pip install --no-cache-dir .; \
    else pip install --no-cache-dir fastapi uvicorn; fi \
    && chown -R codegate:codegate /app

USER codegate
EXPOSE 8001

CMD ["sh", "-c", "exec uvicorn ${AI_APP_MODULE} --host 0.0.0.0 --port ${PORT}"]

