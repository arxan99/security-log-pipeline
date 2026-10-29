FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY slp ./slp
RUN pip install --no-cache-dir . && useradd --create-home slp
USER slp
WORKDIR /data
ENTRYPOINT ["slp", "--db", "/data/slp.db"]
CMD ["--help"]
