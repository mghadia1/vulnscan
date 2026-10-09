# VulnScan in a container. It scans a directory mounted read-only at /scan:
#   docker run --rm --network none -v "$PWD:/scan:ro" vulnscan:local
# A scan needs no network; run it with none.

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && rm -rf /app/src \
    && useradd --create-home --uid 10001 vulnscan

# An unprivileged user: a scanner has no reason to be root.
USER vulnscan
WORKDIR /scan
ENTRYPOINT ["vulnscan"]
CMD ["scan", "/scan"]
