FROM python:3.13-slim

WORKDIR /app

# Install scanner package from PyPI; pin/override via build args when needed.
ARG GUARDMARLY_VERSION=guardmarly
RUN pip install --no-cache-dir "${GUARDMARLY_VERSION}"

ENTRYPOINT ["guardmarly"]
