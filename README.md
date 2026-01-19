### System Requirements:
- cmake and clang (or gcc)
- KeyDB Engine [Check installation guide](KEYDB_INSTALL.md)
- KVRocks engine (if you want to persist more data on disk) [Check installation guide](KVROCKS_INSTALL.MD)
- Memory (RAM): 16 GB
- Processor (CPU): 4 Cores (with AVX2 support)
- Storage (Disk): 100 GB Fast SSD / NVMe

Install dependencies and necessary tools to operate bob:
```
sudo apt-get update;
apt install vim net-tools tmux cmake git libjsoncpp-dev build-essential cmake uuid-dev libhiredis-dev zlib1g-dev unzip pkg-config -y;
```

### Optional: Kafka Support
To enable streaming logs and transactions to Kafka, install librdkafka:
```
apt install librdkafka-dev -y;
```
**Note:** `pkg-config` is required for cmake to detect librdkafka. Without it, Kafka support will be silently disabled.

### BUILD

On Linux, make sure `cmake` and `make` commands are installed and then run:
```
mkdir build;
cd build;
cmake ../;
make;
```

### CONFIGURATION
An example file, `default_config_bob.json`, is provided and contains the minimal configuration required to run bob.

For the trusted-node field, the expected format is `NODE_IP:NODE_PORT:PASSCODE_LOGGING`. If the `PASSCODE_LOGGING` is not available, the simplified format `NODE_IP:NODE_PORT` should be used. 

- Too tight `request-cycle-ms` or `future-offset` may lead to overloading the node.
- `run-server` means opening a server and listening at port `server-port` to serve a few important data (like the core baremetal)
```
{
  "trusted-node": ["BM:157.180.10.49:21841:0-0-0-0","BM:65.109.122.174:21841:0-0-0-0"],
  "request-cycle-ms": 100,
  "request-logging-cycle-ms": 30,
  "future-offset": 3,
  "log-level": "info",
  "keydb-url": "tcp://127.0.0.1:6379",
  "run-server": false,
  "server-port": 21842,
  "arbitrator-identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ",
  "trusted-entities": ["QCTBOBEPDEZGBBCSOWGBYCAIZESDMEVRGLWVNBZAPBIZYEJFFZSPPIVGSCVL"],
  "tick-storage-mode": "kvrocks",
  "kvrocks-url": "tcp://127.0.0.1:6666",
  "tx-storage-mode" : "kvrocks",
  "tx_tick_to_live" : 3000,
  "max-thread": 8,
  "spam-qu-threshold": 100
}
```

### USEFUL RESOURCES
#### Using bob
- [What is logging event in Qubic?](LOGGING_IN_QUBIC.MD)
- [REST API endpoints](REST_API.md)
- [Mastering findlog method](FINDLOG.MD)
- [Dealing with tx and logging in bob](DEAL_WITH_TX.MD)
- Increase kernel buffer size to [improve the stability of lite node](KERN_BUF_SIZE.MD)
#### Inside bob
- [Anatomy of bob](ANATOMY_OF_BOB.MD)
- [Indexer indexing Qubic data](INDEXER_INDEXING_DATA.MD)

### USAGE
`./bob <config_path>`

### INSTALLATION SCRIPTS
All in one batch file for the lazy:
```
apt update && apt upgrade -y;
apt install vim net-tools tmux cmake git libjsoncpp-dev build-essential cmake uuid-dev libhiredis-dev zlib1g-dev unzip pkg-config librdkafka-dev -y;
git clone https://github.com/krypdkat/qubicbob.git;
cd qubicbob;
mkdir build;
cd build;
cmake ..;
make bob -j8;
curl -fsSL https://download.keydb.dev/open-source-dist/keyring.gpg | sudo gpg --dearmor -o /usr/share/keyrings/keydb-archive-keyring.gpg;
echo "deb [signed-by=/usr/share/keyrings/keydb-archive-keyring.gpg] https://download.keydb.dev/open-source-dist jammy main" | sudo tee /etc/apt/sources.list.d/keydb.list;
apt update;
apt install keydb;
```

