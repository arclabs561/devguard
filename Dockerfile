FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Minimal runtime deps:
# - curl: install uv + trufflehog
# - ca-certificates: TLS
# - git: used by some tooling, and harmless to include
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates git \
  && rm -rf /var/lib/apt/lists/*

# Install uv (fast dependency management / runner)
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Install trufflehog (scanner engine for public GitHub sweep)
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin \
  && trufflehog --version

# Install kingfisher (optional engine for deeper scans)
RUN curl --silent --location \
    https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | \
    bash -s -- /usr/local/bin \
  && kingfisher --version

WORKDIR /app

# Cache dependencies separately from source.
COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev --no-install-project

# Copy the project and install it into the venv.
COPY . /app/
RUN uv sync --frozen --no-dev --no-editable

# Expose venv-installed entrypoints (e.g. `devguard`).
ENV PATH="/app/.venv/bin:${PATH}"

# Default to running the CLI.
ENTRYPOINT ["devguard"]
CMD ["--help"]
