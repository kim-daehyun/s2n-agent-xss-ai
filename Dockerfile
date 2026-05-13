FROM python:3.11-slim

ARG APP_VERSION=0.1.0

LABEL org.opencontainers.image.title="S2N Agent URL-to-PDF XSS Reporter"
LABEL org.opencontainers.image.description="Local Docker runner that validates authorized XSS targets and generates PDF reports."
LABEL org.opencontainers.image.version="${APP_VERSION}"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV HF_HOME=/app/storage/huggingface
ENV TRANSFORMERS_CACHE=/app/storage/huggingface
ENV SENTENCE_TRANSFORMERS_HOME=/app/storage/sentence_transformers

ENV PIP_DEFAULT_TIMEOUT=180
ENV PIP_RETRIES=10
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONHTTPSVERIFY=1

WORKDIR /app

# OS packages for:
# - WeasyPrint PDF rendering
# - ChromaDB / sentence-transformers dependencies
# - general build fallback for pinned Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libharfbuzz-subset0 \
    libffi-dev \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    fonts-dejavu-core \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-lock.txt /app/requirements-lock.txt

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /app/requirements-lock.txt

COPY . /app

RUN mkdir -p \
    /app/reports/generated \
    /app/storage/chroma_xss_guides \
    /app/storage/huggingface \
    /app/storage/sentence_transformers

# Interactive URL -> reflected XSS validation -> Normalizer -> ChromaDB RAG -> Official reference mapping -> PDF.

# Browser runtime dependencies for Playwright Chromium.
# Do not use `playwright install --with-deps` here because it may request
# unavailable Ubuntu font packages on this Debian-based image.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcairo2 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libpango-1.0-0 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    fonts-dejavu-core \
    fonts-liberation \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*

RUN python -m playwright install chromium

CMD ["python", "-B", "scripts/plugin_agents/run_url_to_pdf.py"]
