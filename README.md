### System Requirements:
- cmake and clang (or gcc)
- Redis with TimeSeries Module, 8.0.0 (or above)
- Memory (RAM): 16 GB
- Processor (CPU): 4 Cores (with AVX2 support)
- Storage (Disk): 100 GB Fast SSD / NVMe


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
  "trusted-node": ["127.0.0.1:21841:0-0-0-0","46.17.96.249:21841:0-0-0-0"],
  "request-cycle-ms": 100,
  "future-offset": 3,
  "log-level": "info",
  "redis-url": "tcp://127.0.0.1:6379",
  "run-server": true,
  "server-port": 21842,
  "verify-log-event": true,
  "arbitrator-identity": "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ"
}
```

### USAGE
`./bob <config_path>`
