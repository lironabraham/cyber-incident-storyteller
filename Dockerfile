FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

FROM python:3.12-slim

WORKDIR /workspace
COPY --from=builder /usr/local/lib/python3.12 /usr/local/lib/python3.12
COPY --from=builder /usr/local/bin/ais /usr/local/bin/ais

RUN mkdir -p logs reports data/processed

ENTRYPOINT ["ais"]
CMD ["demo"]
