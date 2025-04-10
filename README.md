# Cloudflare Dynamic DNS Updater (C++)

A lightweight and efficient Dynamic DNS updater written in C++. This tool updates your Cloudflare DNS records with your current public IP (IPv4 and/or IPv6), supports multiple records, logs updates with retention, and can run as a systemd service for full automation.

## ✨ Features

- ✅ Cloudflare API v4 integration
- ✅ IPv4 and optional IPv6 support
- ✅ Supports multiple DNS records
- ✅ Systemd service for auto-start and scheduling
- ✅ Log rotation (retain only 30 days of logs)
- ✅ JSON configuration with individual options per record
- ✅ No dependencies beyond `libcurl` and `jsoncpp`

---

## 🔧 Requirements

- C++17 compiler (e.g., `g++`)
- `libcurl` development files
- `jsoncpp` library

Install dependencies (Debian/Ubuntu):

```bash
sudo apt install g++ libcurl4-openssl-dev libjsoncpp-dev
```

---

## ⚙️ Building

```bash
g++ -I/usr/include/jsoncpp cf_ddns_service.cpp -o cf_ddns_service -lcurl -ljsoncpp -std=c++17 -pthread
```

---

## 🛠️ Configuration

Copy and modify the sample config:

```bash
cp config.json.example config.json
```

Edit `config.json` to include your API token, zone ID, and records.

```json
{
  "api_token": "YOUR_API_TOKEN",
  "check_interval": 300,
  "records": [
    {
      "zone_id": "ZONE_ID_1",
      "record_id": "RECORD_ID_1",
      "record_name": "host.example.com",
      "enable_ipv4": true,
      "enable_ipv6": false,
      "enable_proxy": false
    },
    {
      "zone_id": "ZONE_ID_2",
      "record_id": "RECORD_ID_2",
      "record_name": "ipv6.example.com",
      "enable_ipv4": false,
      "enable_ipv6": true,
      "enable_proxy": true
    }
  ]
}

```

---

## 🚀 Running as a Service

### 1. Install the binary and config

Place your compiled binary and `config.json` in `/opt/cf_ddns/`:

```bash
sudo mkdir -p /opt/cf_ddns
sudo cp cf_ddns config.json /opt/cf_ddns/
```

### 2. Install the systemd service

```bash
sudo cp cf_ddns.service /etc/systemd/system/
```

### 3. Enable and start the service

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now cf_ddns.service
```

### 4. Check status and logs

```bash
systemctl status cf_ddns.service
journalctl -u cf_ddns.service -f
```

---

## 📁 Logs

Logs are written to a `logs/` folder in the same directory as the binary (`/opt/cf_ddns/logs`). Old logs are cleaned up automatically based on `log_retention_days`.

---

## 💡 Example Use Cases

- Automatically update your home IP with your domain name.
- Maintain connectivity to your SIP server or VPN endpoint.

---

## 🙏 Credits

Contributions are welcome!

---

## 📜 License

MIT License
