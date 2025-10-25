# How to Install KeyDB and Configure FLASH Storage

This tutorial guides you through installing KeyDB and configuring its **FLASH** feature. The FLASH feature enables KeyDB to use a combination of RAM and a persistent SSD (like an NVMe drive) as a single, large data store. This allows you to store datasets much larger than your available RAM, offering a massive cost saving.

KeyDB treats RAM as a cache for your "hot" (frequently accessed) data, while "cold" (less-used) data is automatically moved to the faster persistent storage (SSD).

---

## Part 1: KeyDB Installation

Choose the installation method that matches your operating system.

### Option 1: Install on Linux (Ubuntu/Debian)

This is the recommended method for a production server.

1.  **Add the KeyDB PPA (Personal Package Archive):**
    ```bash
    curl -s --compressed "[https://download.keydb.dev/keydb-ppa/KEY.gpg](https://download.keydb.dev/keydb-ppa/KEY.gpg)" | sudo apt-key add -
    
    echo "deb [https://download.keydb.dev/open-source-dist](https://download.keydb.dev/open-source-dist) $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/keydb.list
    ```

2.  **Update and Install KeyDB:**
    ```bash
    sudo apt update
    sudo apt install keydb
    ```

3.  **Manage the KeyDB Service:**
    The installer automatically sets up KeyDB to run as a `systemd` service.
    ```bash
    # Start the service
    sudo systemctl start keydb-server
    
    # Check its status
    sudo systemctl status keydb-server
    
    # Enable it to start on boot
    sudo systemctl enable keydb-server
    ```
    The configuration file is located at: `/etc/keydb/keydb.conf`.

### Option 2: Install via Docker (All Platforms)

This is the easiest way to get started on any platform, including **Windows (via WSL2)** and **macOS**.

1.  **Pull the KeyDB Docker Image:**
    ```bash
    docker pull eqalpha/keydb
    ```

2.  **Run a Basic KeyDB Container:**
    ```bash
    docker run -d --name my-keydb -p 6379:6379 eqalpha/keydb
    ```

3.  **Connect using `keydb-cli`:**
    ```bash
    docker exec -it my-keydb keydb-cli
    ```
    *(We will cover the specific Docker command for FLASH storage in Part 3).*
---

## Part 2: Understanding FLASH Configuration

To enable FLASH, you need to edit your `keydb.conf` file and set **three** key directives.

1.  **`storage-provider flash [path]`**
    * This is the most important directive. It tells KeyDB to enable FLASH mode.
    * You must provide a path to a directory on your **fast SSD/NVMe drive**. KeyDB will create its storage files there.
    * **Important:** This directory must be on a high-performance SSD for the feature to be effective.

2.  **`maxmemory [size]`**
    * This directive sets a **hard limit on the amount of RAM** KeyDB can use.
    * This is *required* for FLASH to work. When KeyDB hits this RAM limit, it will evict the least-used data from RAM and move it to the SSD storage you specified.
    * Example: `maxmemory 4gb`

3.  **`maxmemory-policy [policy]`**
    * This tells KeyDB *how* to decide which keys to evict from RAM.
    * The recommended policies for FLASH are:
        * **`allkeys-lru`**: (Least Recently Used) Evicts the keys that haven't been accessed in the longest time.
        * **`allkeys-lfu`**: (Least Frequently Used) Evicts the keys that have been accessed the fewest times.
    * `allkeys-lru` is a great default.

---

## Part 3: How to Configure FLASH (Examples)

Here are practical examples for the installation methods from Part 1.

### Example A: Configure FLASH for a Linux Service (systemd)

1.  **Prepare the Storage Directory:**
    First, create the directory on your NVMe drive and give the `keydb` user ownership.
    ```bash
    # Example: Your SSD is mounted at /mnt/nvme
    sudo mkdir -p /mnt/nvme/keydb-flash
    
    # Give the keydb user/group ownership
    sudo chown -R keydb:keydb /mnt/nvme/keydb-flash
    ```

2.  **Edit `keydb.conf`:**
    Open the configuration file:
    ```bash
    sudo nano /etc/keydb/keydb.conf
    ```
    Add these lines to the file (you can add them near the top or find and uncomment the existing `maxmemory` settings):
    ```ini
    # --- FLASH STORAGE CONFIGURATION ---
    
    # 1. Point to your SSD directory
    storage-provider flash /mnt/nvme/keydb-flash
    
    # 2. Set your RAM limit (e.g., 4 Gigabytes)
    maxmemory 4gb
    
    # 3. Set the eviction policy
    maxmemory-policy allkeys-lru
    
    # -----------------------------------
    ```

3.  **Update systemd Permissions:**
    Since the service is sandboxed, you must explicitly give it permission to write to your new directory.
    ```bash
    # Create an override file for the service
    sudo systemctl edit keydb-server.service
    ```
    This will open a blank text file. Paste the following content into it, save, and exit:
    ```ini
    [Service]
    # Give read/write access to the flash storage path
    ReadWriteDirectories=-/mnt/nvme/keydb-flash
    ```

4.  **Reload and Restart:**
    Reload the `systemd` daemon and restart KeyDB to apply all changes.
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl restart keydb-server
    ```

5.  **Verify:**
    Connect with `keydb-cli` and run the `INFO` command.
    ```bash
    keydb-cli
    > INFO memory
    ```
    Look for the `maxmemory` setting and other memory-related stats. As you add data beyond your `maxmemory` limit, you will see `used_memory` stay near the cap, while the files in `/mnt/nvme/keydb-flash` grow.

### Example B: Configure FLASH with Docker

With Docker, you pass the configuration as command-line arguments and use a volume to map your host's SSD path to the container.

* This single command does everything:
* `-v /mnt/nvme/keydb-flash:/data` maps your host's SSD path `/mnt/nvme/keydb-flash` to the `/data` directory inside the container.
* The `keydb-server` command is appended with all the configuration flags.

```bash
docker run -d --name keydb-flash-instance -p 6379:6379 \
  -v /mnt/nvme/keydb-flash:/data \
  eqalpha/keydb \
  keydb-server /etc/keydb/keydb.conf \
    --storage-provider flash /data \
    --maxmemory 4gb \
    --maxmemory-policy allkeys-lru