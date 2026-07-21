FROM python:3.12.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AI_AUTH_MODE=internal \
    AI_GENERATION_MODE=external \
    AI_REVIEW_MODE=external \
    AI_RUBRIC_MODE=external
WORKDIR /app
RUN groupadd --system --gid 10001 codegate \
    && useradd --system --uid 10001 --gid codegate --home-dir /nonexistent codegate
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=codegate:codegate app ./app

USER codegate
EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
