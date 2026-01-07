# Docker Setup for Qubic Bob

This directory contains Docker configurations for running Qubic Bob in different deployment scenarios.

## Available Images

| Image | Description |
|-------|-------------|
| `j0et0m/qubic-bob-standalone:prod` | All-in-one image with Bob, Redis, and Kvrocks |
| `j0et0m/qubic-bob:prod` | Bob only (requires external Redis/KeyDB and Kvrocks) |

## Directory Structure

```
docker/
├── standalone/          # All-in-one deployment
│   ├── Dockerfile
│   ├── bob.json
│   ├── redis.conf
│   ├── kvrocks.conf
│   └── supervisord.conf
├── compose/             # Docker Compose deployment
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── bob.json
│   ├── keydb.conf
│   └── kvrocks.conf
└── examples/            # Ready-to-use examples with pre-built images
    ├── docker-compose.standalone.yml
    ├── docker-compose.yml
    ├── bob.json
    ├── bob.json.standalone
    ├── keydb.conf
    └── kvrocks.conf
```

---

## Option 1: Standalone (Recommended for Quick Start)

Single container with Bob, Redis, and Kvrocks included.

### Using Pre-built Image

```bash
cd docker/examples

# Bob can run without custom configuration
# For customization use one of our templates
# cp bob.json.standalone bob.json
# Edit bob.json as needed (add p2p-node entries, etc.)

# Run
docker compose -f docker-compose.standalone.yml up -d

# View logs
docker logs -f qubic-bob-standalone
```

### Building from Source

```bash
# From repository root
docker build -t qubic-bob-standalone -f docker/standalone/Dockerfile .

# Run
docker run -d --name qubic-bob-standalone \
  -p 21842:21842 \
  -p 40420:40420 \
#  -v /path/to/bob.json:/app/bob.json:ro \ # optional custom configuration
  -v qubic-bob-redis:/data/redis \
  -v qubic-bob-kvrocks:/data/kvrocks \
  -v qubic-bob-data:/data/bob \
  qubic-bob-standalone
```

### Exposed Ports

| Port | Description |
|------|-------------|
| 21842 | Bob P2P server |
| 40420 | REST API |

### Volumes

| Volume | Description |
|--------|-------------|
| `/data/redis` | Redis persistence data |
| `/data/kvrocks` | Kvrocks persistence data |
| `/data/bob` | Bob snapshot files (spectrum.*, universe.*) |

### Configuration

Mount your own `bob.json` to `/app/bob.json`. For standalone, use localhost addresses:

```json
{
  "p2p-node": [],
  "keydb-url": "tcp://127.0.0.1:6379",
  "kvrocks-url": "tcp://127.0.0.1:6666",
  "run-server": true,
  "server-port": 21842,
  "tick-storage-mode": "kvrocks",
  "tx-storage-mode": "kvrocks",
  "tx_tick_to_live": 10000
}
```

---

## Option 2: Docker Compose (Separate Containers)

Bob runs in its own container, connecting to external KeyDB and Kvrocks containers.

### Using Pre-built Image

```bash
cd docker/examples

# Edit bob.json as needed
# Run
docker compose up -d

# View logs
docker logs -f qubic-bob
```

### Building from Source

```bash
# From repository root
docker build -t qubic-bob -f docker/compose/Dockerfile .

# Then use docker-compose.yml with your built image
```

### Configuration

For compose setup, use container hostnames:

```json
{
  "p2p-node": [],
  "keydb-url": "tcp://keydb:6379",
  "kvrocks-url": "tcp://kvrocks:6666",
  "run-server": true,
  "server-port": 21842,
  "tick-storage-mode": "kvrocks",
  "tx-storage-mode": "kvrocks",
  "tx_tick_to_live": 10000
}
```

---

## Configuration Reference

### bob.json Options

| Option | Description | Default |
|--------|-------------|---------|
| `p2p-node` | Array of P2P nodes to connect to | `[]` (fetches from qubic.global) |
| `keydb-url` | Redis/KeyDB connection URL | - |
| `kvrocks-url` | Kvrocks connection URL | - |
| `run-server` | Enable P2P server | `true` |
| `server-port` | P2P server port | `21842` |
| `tick-storage-mode` | Storage mode: `kvrocks` or `lastNTick` | `kvrocks` |
| `tx-storage-mode` | Transaction storage: `kvrocks` or `free` | `kvrocks` |
| `tx_tick_to_live` | Ticks to keep transaction data | `10000` |
| `max-thread` | Max processing threads (0 = auto) | `0` |
| `log-level` | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `spam-qu-threshold` | Min QU amount to index transfers | `100` |

### P2P Node Format

```json
"p2p-node": [
  "BM:IP:PORT:P0-P1-P2-P3",
  "BM:157.180.10.49:21841:0-0-0-0"
]
```

- `BM:` prefix indicates a trusted node
- `0-0-0-0` Passcode from node (relevant for full node connection)

---

## Managing the Database

### Clean Up (Reset Everything)

**Standalone:**
```bash
docker stop qubic-bob-standalone
docker rm qubic-bob-standalone
docker volume rm qubic-bob-redis qubic-bob-kvrocks qubic-bob-data
```

**Compose:**
```bash
docker compose down -v
```

### Clean While Running

```bash
# Exec into container
docker exec -it qubic-bob-standalone bash

# Clear Redis
redis-cli FLUSHALL

# Clear Kvrocks
redis-cli -p 6666 FLUSHALL

# Remove snapshot files
rm -f /data/bob/spectrum.* /data/bob/universe.*

# Restart container
exit
docker restart qubic-bob-standalone
```

---

## Troubleshooting

### View Logs

```bash
# Standalone
docker logs -f qubic-bob-standalone

# Compose
docker logs -f qubic-bob
docker logs -f qubic-bob-keydb
docker logs -f qubic-bob-kvrocks
```

### Check Service Status (Standalone)

```bash
docker exec -it qubic-bob-standalone supervisorctl status
```

### Common Issues

**"Cannot connect to Kvrocks"**
- Kvrocks hasn't started yet. Bob will retry automatically.

**"Peer certificate is not valid"**
- Missing CA certificates. Ensure `ca-certificates` is installed.

**"No persisted lastCleanTransactionTick found"**
- Normal on first startup or after database cleanup.

**Snapshot file errors**
- Database may be corrupted. Clean up and restart fresh.

---

## Building Images

```bash
# From repository root

# Build standalone image
docker build -t qubic-bob-standalone -f docker/standalone/Dockerfile .

# Build normal image
docker build -t qubic-bob -f docker/compose/Dockerfile .

# replace j0et0m below with your own docker hub user to upload it to your repository

# Tag for Docker Hub
docker tag qubic-bob-standalone j0et0m/qubic-bob-standalone:prod
docker tag qubic-bob j0et0m/qubic-bob:prod

# Push
docker push j0et0m/qubic-bob-standalone:prod
docker push j0et0m/qubic-bob:prod
```
