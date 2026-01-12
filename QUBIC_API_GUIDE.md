# Qubic JSON-RPC API Guide

This guide is for exchange developers and integrators who want to connect to Qubic. If you're familiar with Ethereum's JSON-RPC API, this guide will help you understand the differences and map concepts between the two.


> [!NOTE]
> This documentation covers the Qubic JSON-RPC 2.0 API including WebSocket subscriptions.

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Concept Mapping: Ethereum vs Qubic](#concept-mapping-ethereum-vs-qubic)
4. [API Endpoints](#api-endpoints)
5. [Method Reference](#method-reference)
6. [Code Examples](#code-examples)
7. [WebSocket Subscriptions](#websocket-subscriptions)

---

## Introduction

Qubic uses a JSON-RPC 2.0 API similar to Ethereum, but with terminology and data structures adapted to Qubic's unique architecture. Key differences:

- **Ticks** instead of blocks
- **Identities** (60-character strings) instead of 20-byte addresses
- **Epochs** as time periods (~7 days each)
- **Immediate finality** - no confirmation wait needed
- **No gas** - transactions are free

## Quick Start

### HTTP Endpoint
```
POST http://your-node:40420/qubic
```

### WebSocket Endpoint
```
ws://your-node:40420/ws/qubic
```

### Example: Get Current Tick
```bash
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": 12500000,
  "id": 1
}
```

### Example: Get Balance
```bash
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getBalance","params":["BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID"],"id":1}'
```

---

## Concept Mapping: Ethereum vs Qubic

| Ethereum Concept | Qubic Concept | Notes |
|-----------------|---------------|-------|
| Block | **Tick** | Atomic consensus unit, ~1 second interval |
| Block number | **Tick number** | Sequential 32-bit integer |
| Block hash | **Tick signature** | 64-byte Schnorr signature |
| Address (20 bytes, 0x...) | **Identity** (60 chars) | Encoded public key (A-Z) |
| Private key | **Seed** (55 lowercase letters) | Used to derive identity |
| wei/gwei/ether | **QU** | No decimals, raw integer units |
| Gas limit/price | N/A | Qubic has no gas fees |
| Confirmations | N/A | Ticks are immediately final |
| ERC-20 tokens | **Native assets** | Built-in asset support |
| Smart contracts | **Smart contracts** | Index 1-65535 |
| - | **Epoch** | ~7 day period, resets state |

### Identity Format

Qubic identities are 60-character uppercase strings:
```
BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFUDG
└──────────────────── 56 chars ────────────────────────┘└4─┘
                      address                           checksum
```

**Structure:**
- **56 characters**: The address derived from the 32-byte public key
- **4 characters**: Checksum (KangarooTwelve hash of public key)

**Encoding Algorithm:**
The 32-byte public key is split into 4 chunks of 8 bytes. Each chunk is treated as a 64-bit integer and converted to 14 characters by repeatedly dividing by 26 (remainder → A-Z). The checksum is derived from `KangarooTwelve(publicKey, 32)`, masked to 18 bits, and encoded as 4 characters.

**Checksum Validation:**
To validate an identity, recompute the checksum from the public key (decoded from the first 56 characters) and compare with the last 4 characters. Invalid checksums indicate a typo or corrupted address.

The API also accepts hex format (0x + 64 hex chars) for compatibility:
```
0x0000000000000000000000000000000000000000000000000000000000000000
```

Responses always return the 60-character Qubic identity format (uppercase).

### Transaction Hash Format

Transaction hashes are 60-character lowercase strings with the same structure:
```
abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh
└──────────────────── 56 chars ────────────────────────┘└4─┘
                      hash                              checksum
```

**Structure:**
- **56 characters**: The hash derived from 32 bytes (same algorithm as identity, but lowercase)
- **4 characters**: Checksum (KangarooTwelve hash, encoded as a-z)

**Key Difference:**
- Identities (addresses): **UPPERCASE** (A-Z)
- Transaction hashes: **lowercase** (a-z)

### Tick Tags

Similar to Ethereum block tags:

| Tag | Meaning |
|-----|---------|
| `"latest"` | Latest verified tick |
| `"earliest"` | First tick of current epoch |
| `"pending"` | Current fetching tick (not yet verified) |
| `12500000` | Specific tick number (decimal) |
| `"0xbebc20"` | Specific tick number (hex) |

---

## API Endpoints

| Endpoint | Protocol | Description |
|----------|----------|-------------|
| `/qubic` | HTTP POST | JSON-RPC 2.0 requests |
| `/ws/qubic` | WebSocket | Real-time subscriptions |

---

## Method Reference

### Chain Info Methods

#### qubic_chainId
Returns chain identification info.

Chain IDs are derived deterministically from `keccak256("qubic:<network>")[-4:]`:

| Network | Chain ID (Decimal) | Chain ID (Hex) |
|---------|-------------------|----------------|
| mainnet | 788278422 | 0x2efc2c96 |
| testnet | 1997427496 | 0x770e5328 |
| devnet | 7948451 | 0x007948a3 |
| simnet | 3266082397 | 0xc2ac765d |

**Request:**
```json
{"jsonrpc":"2.0","method":"qubic_chainId","params":[],"id":1}
```

**Response:**
```json
{
  "result": {
    "chainId": "0x2efc2c96",
    "chainIdDecimal": 788278422,
    "network": "qubic-mainnet"
  }
}
```

| Ethereum Equivalent | Notes |
|---------------------|-------|
| `eth_chainId` | Returns more info in Qubic format |

---

#### qubic_clientVersion
Returns client version string.

**Response:** `"QubicBob/1.1.2"`

| Ethereum Equivalent |
|---------------------|
| `web3_clientVersion` |

---

#### qubic_syncing
Returns sync status with detailed tick progress.

**Response (syncing):**
```json
{
  "result": {
    "syncing": true,
    "epoch": 150,
    "initialTick": 12000000,
    "lastSeenNetworkTick": 12500000,
    "currentFetchingTick": 12490000,
    "currentFetchingLogTick": 12480000,
    "currentVerifyLoggingTick": 12450000,
    "currentIndexingTick": 12449999,
    "progress": 0.9
  }
}
```

**Response (synced):**
```json
{
  "result": {
    "syncing": false,
    "epoch": 150,
    "initialTick": 12000000,
    "lastSeenNetworkTick": 12500000,
    "currentFetchingTick": 12500000,
    "currentFetchingLogTick": 12500000,
    "currentVerifyLoggingTick": 12500000,
    "currentIndexingTick": 12499999
  }
}
```

**Tick Status Fields:**
| Field | Description |
|-------|-------------|
| `lastSeenNetworkTick` | Last seen tick of the Qubic network (omitted if unknown) |
| `currentFetchingTick` | Latest tick being fetched from network |
| `currentFetchingLogTick` | Latest tick with logs being fetched |
| `currentVerifyLoggingTick` | Latest tick with verified logs |
| `currentIndexingTick` | Latest tick indexed in database |

**Sync Determination:**
- If `lastSeenNetworkTick` is available: synced when `lastSeenNetworkTick - 10 <= currentVerifyLoggingTick`
- Fallback (network tick unknown): synced when `currentFetchingTick - 10 <= currentVerifyLoggingTick`

| Ethereum Equivalent |
|---------------------|
| `eth_syncing` |

---

#### qubic_getCurrentEpoch
Returns current epoch info including tick range and log boundaries.

**Response:**
```json
{
  "result": {
    "epoch": 192,
    "currentTick": 39900000,
    "initialTick": 39862000,
    "endTick": 0,
    "endTickStartLogId": -1,
    "endTickEndLogId": -3
  }
}
```

**Fields:**
| Field | Description |
|-------|-------------|
| `epoch` | Current epoch number |
| `currentTick` | Latest verified tick |
| `initialTick` | First tick of this epoch |
| `endTick` | Last tick of this epoch (0 if epoch still active) |
| `endTickStartLogId` | Starting log ID for end-of-epoch events (-1 if not available) |
| `endTickEndLogId` | Ending log ID for end-of-epoch events |

| Ethereum Equivalent |
|---------------------|
| N/A (Qubic-specific) |

---

### Tick Methods

#### qubic_getTickNumber
Returns latest verified tick number.

**Response:** `12500000`

| Ethereum Equivalent |
|---------------------|
| `eth_blockNumber` |

---

#### qubic_getTickByNumber
Returns tick data by number or tag.

**Params:** `[tickTag, includeTransactions]`
- `tickTag`: `"latest"`, `"earliest"`, `"pending"`, or numeric tick number
- `includeTransactions`: `true` for full transaction objects, `false` for hashes only

**Request (hashes only):**
```json
{"jsonrpc":"2.0","method":"qubic_getTickByNumber","params":["latest", false],"id":1}
```

**Response (includeTransactions=false):**
```json
{
  "result": {
    "tickNumber": 12500000,
    "epoch": 150,
    "computorIndex": 42,
    "signature": "0x...",
    "tickHash": "0x...",
    "timestamp": 1705312245,
    "timestampISO": "2025-01-15T10:30:45Z",
    "millisecond": 500,
    "timelock": "0x...",
    "transactionCount": 2,
    "transactions": [
      "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
      "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi"
    ],
    "previousTickHash": "0x..."
  }
}
```

**Request (full transactions):**
```json
{"jsonrpc":"2.0","method":"qubic_getTickByNumber","params":[12500000, true],"id":1}
```

**Response (includeTransactions=true):**
```json
{
  "result": {
    "tickNumber": 12500000,
    "epoch": 150,
    "computorIndex": 42,
    "signature": "0x...",
    "tickHash": "0x...",
    "timestamp": 1705312245,
    "timestampISO": "2025-01-15T10:30:45Z",
    "millisecond": 500,
    "timelock": "0x...",
    "transactionCount": 2,
    "transactions": [
      {
        "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
        "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "amount": 1000000,
        "inputType": 0,
        "inputSize": 0,
        "inputData": ""
      },
      {
        "hash": "bcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghi",
        "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
        "amount": 5000000,
        "inputType": 1,
        "inputSize": 32,
        "inputData": "0x0102030405..."
      }
    ],
    "previousTickHash": "0x..."
  }
}
```

**Transaction Object Fields:**
| Field | Description |
|-------|-------------|
| `hash` | 60-char Qubic transaction hash (lowercase) |
| `from` | Sender identity (60 chars, uppercase) |
| `to` | Recipient identity (60 chars, uppercase) |
| `amount` | Transfer amount in QU (integer) |
| `inputType` | Transaction type (0=transfer, >0=SC call) |
| `inputSize` | Size of input data in bytes |
| `inputData` | Hex-encoded input data (empty string if none) |

| Ethereum Equivalent |
|---------------------|
| `eth_getBlockByNumber` |

---

#### qubic_getTickByHash

**Status: NOT AVAILABLE**

This method is currently disabled. Unlike Ethereum where block hashes are indexed, Qubic does not maintain a tick hash → tick number index. Implementing this would require scanning all ticks, which is inefficient.

Use `qubic_getTickByNumber` instead if you know the tick number.

| Ethereum Equivalent |
|---------------------|
| `eth_getBlockByHash` (no Qubic equivalent) |

---

### Transaction Methods

#### qubic_getTransactionByHash
Returns transaction by hash.

**Params:** `[txHash]` - Accepts 60-char Qubic hash (lowercase) or 0x hex format

**Response:**
```json
{
  "result": {
    "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
    "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "amount": 1000000000,
    "tick": 12500000,
    "inputType": 0,
    "inputSize": 0,
    "inputData": ""
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getTransactionByHash` |

---

#### qubic_getTransactionReceipt
Returns transaction receipt with logs.

**Params:** `[txHash]` - Accepts 60-char Qubic hash (lowercase) or 0x hex format

**Response:**
```json
{
  "result": {
    "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
    "tick": 12500000,
    "tickHash": "0x...",
    "transactionIndex": 3,
    "epoch": 150,
    "from": "SOURCEIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "to": "DESTIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "amount": 1000000000,
    "inputType": 0,
    "executed": true,
    "status": "success",
    "logs": [...],
    "logCount": 2
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getTransactionReceipt` |

---

### Balance & Transfer Methods

#### qubic_getBalance
Returns balance and transfer stats for an identity.

**Params:** `[identity]`

**Response:**
```json
{
  "result": {
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "publicKeyHex": "0x...",
    "balance": "1000000000000",
    "incomingAmount": "1500000000000",
    "outgoingAmount": "500000000000",
    "numberOfIncomingTransfers": 100,
    "numberOfOutgoingTransfers": 50,
    "latestIncomingTransferTick": 12499900,
    "latestOutgoingTransferTick": 12499500,
    "currentTick": 12500000
  }
}
```

| Ethereum Equivalent | Notes |
|---------------------|-------|
| `eth_getBalance` | Returns much more data |

---

#### qubic_getTransfers
Returns transfers/logs matching filter criteria. Uses the same filter format as the `/findLog` REST endpoint.

**Params:** `[filterObject]`

**Filter Object:**

The filter object follows the same format as the `/findLog` endpoint. See [FINDLOG.MD](FINDLOG.MD) for complete documentation on filter parameters, topic usage, and examples.

| Field | Type | Description |
|-------|------|-------------|
| `identity` | string | Optional. Filter by source or destination identity (JSON-RPC extension) |
| `fromTick` | number | Starting tick number |
| `toTick` | number | Ending tick number |
| `scIndex` | number | Smart contract index. 0 for protocol logs (default: 0) |
| `logType` | number | Log type filter |
| `topic1` | string | Topic filter 1 (source for protocol logs) |
| `topic2` | string | Topic filter 2 (destination for protocol logs) |
| `topic3` | string | Topic filter 3 (extra info) |

> **Wildcard Filter:** Use `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB` to match any value for topic filters.

**Log Types:**

> **Note:** Log types are derived from Qubic core. The latest version can be found at:
> https://github.com/qubic/core/blob/main/src/logging/logging.h

| Type | Name | Description |
|------|------|-------------|
| 0 | QU_TRANSFER | Native QU token transfer |
| 1 | ASSET_ISSUANCE | New asset created |
| 2 | ASSET_OWNERSHIP_CHANGE | Asset ownership transferred |
| 3 | ASSET_POSSESSION_CHANGE | Asset possession transferred |
| 4 | CONTRACT_ERROR_MESSAGE | Smart contract error log |
| 5 | CONTRACT_WARNING_MESSAGE | Smart contract warning log |
| 6 | CONTRACT_INFORMATION_MESSAGE | Smart contract info log |
| 7 | CONTRACT_DEBUG_MESSAGE | Smart contract debug log |
| 8 | BURNING | QU tokens burned |
| 9 | DUST_BURNING | Dust amounts burned |
| 10 | SPECTRUM_STATS | Spectrum statistics |
| 11 | ASSET_OWNERSHIP_MANAGING_CONTRACT_CHANGE | Asset ownership managing contract changed |
| 12 | ASSET_POSSESSION_MANAGING_CONTRACT_CHANGE | Asset possession managing contract changed |
| 13 | CONTRACT_RESERVE_DEDUCTION | Contract reserve deduction |
| 255 | CUSTOM_MESSAGE | Custom message (see subtypes below) |

**Custom Message Subtypes (opCode in log data):**
| OpCode | Name | Description |
|--------|------|-------------|
| 6217575821008262227 | STA_DDIV | Start distribute dividends |
| 6217575821008457285 | END_DDIV | End distribute dividends |
| 4850183582582395987 | STA_EPOC | Start epoch |
| 4850183582582591045 | END_EPOC | End epoch |

**Request (simple - QU transfers for identity):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "fromTick": 12490000,
    "toTick": 12500000
  }],
  "id": 1
}
```

**Response:**
```json
{
  "result": {
    "identity": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
    "fromTick": 12490000,
    "toTick": 12500000,
    "transfers": [
      {
        "ok": true,
        "epoch": 150,
        "tick": 12495000,
        "type": 0,
        "logId": 12345678,
        "logDigest": "a1b2c3d4e5f60718",
        "bodySize": 72,
        "logTypename": "QU_TRANSFER",
        "timestamp": "25-01-11 14:30:45",
        "txHash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
        "body": {
          "from": "ANOTHERIDENTITYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          "to": "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID",
          "amount": 1000000
        },
        "direction": "incoming"
      }
    ],
    "count": 1
  }
}
```

**Request (all protocol logs in tick range - no identity filter):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "fromTick": 12490000,
    "toTick": 12490010,
    "logType": 0
  }],
  "id": 1
}
```

**Request (smart contract logs with topic filters):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_getTransfers",
  "params": [{
    "fromTick": 12490000,
    "toTick": 12500000,
    "scIndex": 1,
    "logType": 6,
    "topic1": "FILTERIDENTITY1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }],
  "id": 1
}
```

**Response (smart contract logs):**
```json
{
  "result": {
    "fromTick": 12490000,
    "toTick": 12500000,
    "scIndex": 1,
    "logType": 6,
    "transfers": [
      {
        "tick": 12495000,
        "epoch": 150,
        "logId": 12345680,
        "logType": 6,
        "logTypeName": "CONTRACT_INFO",
        "contractIndex": 1,
        "contractLogType": 42,
        "rawData": "0x..."
      }
    ],
    "count": 1
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` with transfer event filter |

---

### Asset Methods

#### qubic_getAssetBalance
Returns asset balance for an identity.

**Params:** `[identity, issuer, assetName]`

**Response:**
```json
{
  "result": {
    "identity": "...",
    "issuer": "...",
    "assetName": "QFT",
    "ownershipBalance": "1000000",
    "possessionBalance": "1000000"
  }
}
```

| Ethereum Equivalent |
|---------------------|
| ERC-20 `balanceOf` call |

---

### Log Methods

#### qubic_getLogs
Returns logs matching filter.

**Params:** Filter object:
```json
{
  "fromTick": "latest",
  "toTick": "latest",
  "identity": ["IDENTITY1...", "IDENTITY2..."],
  "logType": [0, 1, 2]
}
```

**Log Types:**

See the complete log types table in [qubic_getTransfers](#qubic_gettransfers) section above.

**Response:**
```json
{
  "result": [
    {
      "tick": 12500000,
      "epoch": 150,
      "logId": 12345678,
      "logIndex": 0,
      "transactionIndex": 3,
      "logType": 0,
      "logTypeName": "QU_TRANSFER",
      "transactionHash": "...",
      "source": "...",
      "destination": "...",
      "amount": "1000000",
      "rawData": "0x..."
    }
  ]
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_getLogs` |

---

## Code Examples

### JavaScript (Node.js)

```javascript
const axios = require('axios');

const RPC_URL = 'http://localhost:40420/qubic';

async function rpc(method, params = []) {
  const response = await axios.post(RPC_URL, {
    jsonrpc: '2.0',
    method,
    params,
    id: 1
  });
  return response.data.result;
}

// Get balance
async function getBalance(identity) {
  return await rpc('qubic_getBalance', [identity]);
}

// Get latest tick
async function getLatestTick() {
  return await rpc('qubic_getTickNumber');
}

// Track deposits for an identity
async function trackDeposits(identity, fromTick) {
  const latestTick = await getLatestTick();
  const transfers = await rpc('qubic_getTransfers', [{
    identity: identity,
    fromTick: fromTick.toString(),
    toTick: latestTick.toString()
  }]);

  return transfers.transfers.filter(t => t.direction === 'incoming');
}

// Query smart contract logs with topic filters
async function getSCLogs(scIndex, logType, topic1, fromTick, toTick) {
  return await rpc('qubic_getTransfers', [{
    scIndex: scIndex,
    logType: logType,
    topic1: topic1,
    fromTick: fromTick,
    toTick: toTick
  }]);
}

// Example usage
(async () => {
  const identity = 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID';

  const balance = await getBalance(identity);
  console.log('Balance:', balance.balance);

  const deposits = await trackDeposits(identity, 12490000);
  console.log('Deposits:', deposits);
})();
```

### Python

```python
import requests
import json

RPC_URL = 'http://localhost:40420/qubic'

def rpc(method, params=None):
    payload = {
        'jsonrpc': '2.0',
        'method': method,
        'params': params or [],
        'id': 1
    }
    response = requests.post(RPC_URL, json=payload)
    return response.json()['result']

def get_balance(identity):
    return rpc('qubic_getBalance', [identity])

def get_latest_tick():
    return rpc('qubic_getTickNumber')

def get_transaction_receipt(tx_hash):
    return rpc('qubic_getTransactionReceipt', [tx_hash])

# Example: Track deposits
identity = 'BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID'
balance = get_balance(identity)
print(f"Balance: {balance['balance']} QU")
print(f"Incoming transfers: {balance['numberOfIncomingTransfers']}")
```

### cURL

```bash
# Get tick number
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":1}'

# Get balance
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getBalance","params":["YOUR_IDENTITY"],"id":1}'

# Get transfers for identity
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTransfers","params":[{"identity":"YOUR_IDENTITY","fromTick":12490000,"toTick":12500000}],"id":1}'

# Get smart contract logs with topic filter
curl -X POST http://localhost:40420/qubic \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qubic_getTransfers","params":[{"scIndex":1,"logType":6,"fromTick":12490000,"toTick":12500000,"topic1":"FILTERIDENTITY..."}],"id":1}'
```

### WebSocket (JavaScript - tickStream)

```javascript
const WebSocket = require('ws');

const ws = new WebSocket('ws://localhost:40420/ws/qubic');

ws.on('open', () => {
  console.log('Connected to Qubic RPC WebSocket');

  // Subscribe to tickStream with filters
  ws.send(JSON.stringify({
    jsonrpc: '2.0',
    method: 'qubic_subscribe',
    params: ['tickStream', {
      txFilters: [],      // Empty = all transactions
      logFilters: [],     // Empty = all logs
      skipEmptyTicks: false,
      includeInputData: true
    }],
    id: 1
  }));
});

ws.on('message', (data) => {
  const msg = JSON.parse(data);

  // Handle subscription confirmation
  if (msg.id === 1 && msg.result) {
    console.log('Subscribed with ID:', msg.result);
    return;
  }

  // Handle tick stream notifications
  if (msg.method === 'qubic_subscription') {
    const tick = msg.params.result;
    console.log(`Tick ${tick.tick}: ${tick.filteredTxs} txs, ${tick.filteredLogs} logs`);

    // Process transactions
    for (const tx of tick.transactions) {
      console.log(`  TX: ${tx.hash.slice(0, 20)}... ${tx.from.slice(0, 10)} -> ${tx.to.slice(0, 10)} ${tx.amount} QU`);
      if (tx.executed) {
        console.log(`      Executed: logs ${tx.logIdFrom} - ${tx.logIdFrom + tx.logIdLength - 1}`);
      }
    }

    // Process logs
    for (const log of tick.logs) {
      if (log.logType === 0) {  // QU_TRANSFER
        console.log(`  LOG: ${log.source.slice(0, 10)} -> ${log.destination.slice(0, 10)} ${log.amount} QU`);
      }
    }
  }
});

ws.on('close', () => {
  console.log('Disconnected');
});
```

---

## WebSocket Subscriptions

Connect to `ws://your-node:40420/ws/qubic` for real-time updates.

### Available Subscription Types

| Type | Description |
|------|-------------|
| `newTicks` | New tick notifications |
| `logs` | Log events matching filter |
| `transfers` | QU transfer events (specialized log filter) |
| `tickStream` | Full tick stream with transactions and logs |

---

### Subscribe to New Ticks

```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["newTicks"],
  "id": 1
}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_0","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_0",
    "result": {
      "tickNumber": 12500001,
      "epoch": 150,
      ...
    }
  }
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_subscribe` with `"newHeads"` |

---

### Subscribe to Transfers

Monitor transfers for specific identities:

```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["transfers", {"identity": ["YOUR_IDENTITY"]}],
  "id": 1
}
```

---

### Subscribe to Logs

```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["logs", {
    "identity": ["IDENTITY1...", "IDENTITY2..."],
    "logType": [0, 2]
  }],
  "id": 1
}
```

| Ethereum Equivalent |
|---------------------|
| `eth_subscribe` with `"logs"` |

---

### Subscribe to Tick Stream

The `tickStream` subscription provides a comprehensive real-time stream of ticks with full transaction and log data.

**newTicks vs tickStream Comparison:**

| Aspect | `newTicks` | `tickStream` |
|--------|-----------|--------------|
| **Purpose** | Lightweight tick notification | Comprehensive tick data stream |
| **Data included** | Basic tick metadata only | Full transactions + logs |
| **Filtering** | None | Transaction and log filters |
| **Catch-up** | No | Yes (via `startTick`) |
| **Use case** | Know when new tick arrives | Process all chain activity |

**When to use which:**

- **Use `newTicks`** when you just need to know a tick happened and will fetch specific data via HTTP calls afterward, or when you want minimal bandwidth.
- **Use `tickStream`** when you need all transactions and logs in real-time, are building an explorer or indexer, need transaction execution status immediately, or want historical data via catch-up.

This is ideal for:
- Building real-time block explorers
- Monitoring all chain activity
- Syncing external systems with the chain

**Request (basic - all ticks with all data):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["tickStream", {}],
  "id": 1
}
```

**Request (with filters):**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscribe",
  "params": ["tickStream", {
    "txFilters": [
      {
        "from": "SOURCEIDENTITY...",
        "to": "DESTIDENTITY...",
        "minAmount": 1000000,
        "inputType": 0
      }
    ],
    "logFilters": [
      {
        "scIndex": 0,
        "logType": 0,
        "transferMinAmount": 1000000
      }
    ],
    "startTick": 12490000,
    "skipEmptyTicks": false,
    "includeInputData": true
  }],
  "id": 1
}
```

**Filter Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `txFilters` | array | `[]` | Transaction filters (empty = all transactions) |
| `logFilters` | array | `[]` | Log filters (empty = all logs) |
| `startTick` | number | `0` | Start tick for catch-up (0 = current tick only) |
| `skipEmptyTicks` | boolean | `false` | Skip ticks with no matching data (heartbeat every 120 ticks) |
| `includeInputData` | boolean | `true` | Include full inputData hex in transactions |

**Transaction Filter Fields (`txFilters`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `from` | string | `""` | Source identity filter (empty = any) |
| `to` | string | `""` | Destination identity filter (empty = any) |
| `minAmount` | number | `0` | Minimum transfer amount |
| `inputType` | number | `-1` | Input type filter (-1 = any, 0 = basic transfer, >0 = SC call) |

**Log Filter Fields (`logFilters`):**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `scIndex` | number | `0` | Smart contract index (0 = protocol logs) |
| `logType` | number | `0` | Log type filter |
| `transferMinAmount` | number | `0` | Minimum amount for QU_TRANSFER events |

**Response:**
```json
{"jsonrpc":"2.0","result":"qubic_sub_1","id":1}
```

**Subscription notifications:**
```json
{
  "jsonrpc": "2.0",
  "method": "qubic_subscription",
  "params": {
    "subscription": "qubic_sub_1",
    "result": {
      "epoch": 150,
      "tick": 12500001,
      "isCatchUp": false,
      "timestamp": "2025-01-15T10:30:45Z",
      "totalLogs": 42,
      "filteredLogs": 5,
      "totalTxs": 15,
      "filteredTxs": 3,
      "transactions": [
        {
          "hash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
          "from": "SOURCEIDENTITY...",
          "to": "DESTIDENTITY...",
          "amount": 1000000,
          "inputType": 0,
          "inputSize": 0,
          "inputData": "",
          "executed": true,
          "logIdFrom": 12345678,
          "logIdLength": 2
        }
      ],
      "logs": [
        {
          "ok": true,
          "epoch": 150,
          "tick": 12500001,
          "type": 0,
          "logId": 12345678,
          "logDigest": "a1b2c3d4e5f60718",
          "bodySize": 72,
          "logTypename": "QU_TRANSFER",
          "timestamp": "25-01-11 14:30:45",
          "txHash": "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefgh",
          "body": {
            "from": "SOURCEIDENTITY...",
            "to": "DESTIDENTITY...",
            "amount": 1000000
          }
        }
      ]
    }
  }
}
```

**Result Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `epoch` | number | Current epoch |
| `tick` | number | Tick number |
| `isCatchUp` | boolean | `true` if this is historical data from catch-up |
| `timestamp` | string | ISO 8601 timestamp of the tick |
| `totalLogs` | number | Total logs in tick (before filtering) |
| `filteredLogs` | number | Number of logs matching filter |
| `totalTxs` | number | Total transactions in tick (before filtering) |
| `filteredTxs` | number | Number of transactions matching filter |
| `transactions` | array | Filtered transactions |
| `logs` | array | Filtered logs |

**Transaction Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `hash` | string | 60-char transaction hash (lowercase) |
| `from` | string | Source identity |
| `to` | string | Destination identity |
| `amount` | number | Transfer amount in QU |
| `inputType` | number | Transaction type (0=transfer, >0=SC call) |
| `inputSize` | number | Size of input data in bytes |
| `inputData` | string | Hex-encoded input data (if `includeInputData` is true) |
| `executed` | boolean | Whether the transaction was executed |
| `logIdFrom` | number | Starting log ID for this transaction (-1 if no logs) |
| `logIdLength` | number | Number of logs generated by this transaction |

**Catch-Up Behavior:**

When `startTick` is specified and is less than the current tick:
1. The subscription is created immediately
2. Historical ticks from `startTick` to current are sent with `isCatchUp: true`
3. After catch-up completes, real-time ticks continue with `isCatchUp: false`

**Heartbeat Ticks:**

When `skipEmptyTicks` is `true`, ticks with no matching transactions or logs are skipped. However, every 120th tick is always sent as a heartbeat to confirm the connection is alive.

---

### Unsubscribe

```json
{
  "jsonrpc": "2.0",
  "method": "qubic_unsubscribe",
  "params": ["qubic_sub_0"],
  "id": 1
}
```

**Response:**
```json
{"jsonrpc":"2.0","result":true,"id":1}
```

---

## Method Mapping Quick Reference

| Ethereum Method | Qubic Method |
|-----------------|--------------|
| `eth_chainId` | `qubic_chainId` |
| `web3_clientVersion` | `qubic_clientVersion` |
| `eth_syncing` | `qubic_syncing` |
| `eth_blockNumber` | `qubic_getTickNumber` |
| `eth_getBlockByNumber` | `qubic_getTickByNumber` |
| `eth_getBlockByHash` | `qubic_getTickByHash` (disabled) |
| `eth_getTransactionByHash` | `qubic_getTransactionByHash` |
| `eth_getTransactionReceipt` | `qubic_getTransactionReceipt` |
| `eth_getBalance` | `qubic_getBalance` |
| `eth_getLogs` | `qubic_getLogs` |
| `eth_subscribe("newHeads")` | `qubic_subscribe("newTicks")` |
| `eth_subscribe("logs")` | `qubic_subscribe("logs")` |
| N/A | `qubic_subscribe("transfers")` |
| N/A | `qubic_subscribe("tickStream")` |
| `eth_unsubscribe` | `qubic_unsubscribe` |
| N/A | `qubic_getCurrentEpoch` |
| N/A | `qubic_getTransfers` |
| N/A | `qubic_getAssetBalance` |
| N/A | `qubic_getAssets` (not implemented) |
| N/A | `qubic_broadcastTransaction` (not implemented) |

---

## Error Codes

Standard JSON-RPC 2.0 error codes:

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Missing required fields |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Wrong parameter types |
| -32603 | Internal error | Server error |
| -32001 | Resource not found | Tick/transaction not found |
| -32002 | Resource unavailable | Node not synced |
| -32005 | Limit exceeded | Query range too large |

---

## Best Practices for Exchanges (Qubic, Qu)

1. **Track deposits by identity**: Use `qubic_getTransfers` with your deposit addresses, logType `QU_TRANSFER`
2. **Poll vs subscribe**: Use WebSocket subscriptions for real-time, HTTP for historical
3. **Real-time streaming**: Use `tickStream` subscription for comprehensive real-time chain monitoring with transaction execution status
4. **No confirmations needed**: Qubic ticks are immediately final
5. **Epoch awareness**: Balance/state resets at epoch boundaries
6. **Rate limiting**: Limit log queries to 1000 ticks max per request
7. **Identity validation**: Verify identities (60 uppercase characters; checksum)
8. **Transaction execution**: Check `executed` field in tickStream transactions to verify successful execution
