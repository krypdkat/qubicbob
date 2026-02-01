# Build stage for bob
FROM ubuntu:24.04 AS bob-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    uuid-dev \
    libhiredis-dev \
    zlib1g-dev \
    libjsoncpp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Build stage for kvrocks
FROM ubuntu:24.04 AS kvrocks-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libsnappy-dev \
    autoconf \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN git clone --depth 1 --branch v2.9.0 https://github.com/apache/kvrocks.git && \
    cd kvrocks && \
    ./x.py build -DPORTABLE=haswell -j$(nproc)

# Runtime stage - standalone with Redis and Kvrocks
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies, Redis, and supervisor
RUN apt-get update && apt-get install -y \
    libssl3t64 \
    libuuid1 \
    libsnappy1v5 \
    libhiredis1.1.0 \
    libjsoncpp25 \
    ca-certificates \
    wget \
    unzip \
    supervisor \
    redis-server \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built binaries
COPY --from=bob-builder /app/build/bob /app/bob
COPY --from=kvrocks-builder /build/kvrocks/build/kvrocks /usr/local/bin/kvrocks

# Create directories for persistent data
RUN mkdir -p /data/redis /data/kvrocks /data/bob /app/logs /etc/kvrocks

# Copy config templates
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/redis.conf /etc/redis/redis.conf
COPY docker/kvrocks.conf /etc/kvrocks/kvrocks.conf
COPY docker/bob.json /app/bob.json

# Expose ports
# 21842 - bob server port
# 40420 - REST API port
EXPOSE 21842 40420

# Data volumes for persistence
VOLUME ["/data/redis", "/data/kvrocks", "/data/bob"]

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
