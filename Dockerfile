# Herald room broker — build context is this directory (FOSS tree or monorepo path).
#
# FOSS / from this folder:
#   docker build -t herald-broker .
#   docker run -d --name=herald_prod --restart=unless-stopped -p 8787:8787 \
#     --ulimit nofile=65535:65535 \
#     -e HERALD_BROKER_PORT=8787 -e HERALD_BROKER_VERBOSE=0 herald-broker
#
# Monorepo (Railway / local): set Docker build context to herald/herald-broker/
#   docker build -f herald/herald-broker/Dockerfile -t herald-broker herald/herald-broker

FROM gcc:13-bookworm AS build
WORKDIR /src
RUN apt-get update \
    && apt-get install -y --no-install-recommends zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY herald_broker.c wire.h ./
RUN gcc -Wall -Wextra -Werror -std=c99 -O2 -DNDEBUG \
    -o herald_broker herald_broker.c -lpthread -lz

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 herald \
    && useradd --uid 65532 --gid 65532 --no-create-home \
       --home-dir /app --shell /bin/false herald
COPY --from=build /src/herald_broker /app/herald_broker
RUN chown herald:herald /app/herald_broker

ENV HERALD_BROKER_PORT=8787
ENV HERALD_BROKER_BIND=0.0.0.0
ENV HERALD_BROKER_VERBOSE=0
ENV HERALD_BROKER_MAX_CONNECTIONS=8192

EXPOSE 8787
USER herald
# Soft-raise nofile when the host/container hard limit allows it. Prefer also
# passing --ulimit nofile=65535:65535 (or platform equivalent) at run time.
CMD ["sh", "-c", "ulimit -n 65535 2>/dev/null || true; exec /app/herald_broker"]
