# Shared image for api / worker / cli.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 1) Deps layer (cached unless requirements.txt changes)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 2) App layer
COPY . .
RUN pip install --no-cache-dir -e . --no-deps

EXPOSE 8000
CMD ["uvicorn", "sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
