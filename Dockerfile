# VulnScan in a container. It scans a directory mounted read-only at /scan:
#   docker run --rm --network none -v "$PWD:/scan:ro" vulnscan:local
# A scan needs no network; run it with none. Advisory data is kept in /data
# (mount ~/.cache/vulnscan there): `update` writes it, and is the only
# command that needs the network; `lookup` and scans read it, read-only.

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VULNSCAN_DATA=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --no-cache-dir . \
    && rm -rf /app/src \
    && useradd --create-home --uid 10001 vulnscan \
    && mkdir /data && chown vulnscan:vulnscan /data

# An unprivileged user: a scanner has no reason to be root.
USER vulnscan
WORKDIR /scan
ENTRYPOINT ["vulnscan"]
CMD ["scan", "/scan"]
