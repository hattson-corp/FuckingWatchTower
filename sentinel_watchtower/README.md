# Sentinel Watchtower - Bug Bounty Automation System

🛡️ **Production-ready automated bug bounty hunting system with Telegram alerts**

## Features

- ✅ **Active Subdomain Discovery** (Subfinder, Assetfinder, Findomain, DNSX)
- ✅ **HTTP Probing & Port Scanning** (httpx, naabu)
- ✅ **Vulnerability Scanning** (Nuclei integration)
- ✅ **XSS Detection** (Dalfox integration)
- ✅ **Web Crawling** (Katana, Gau, Waybackurls)
- ✅ **Telegram Bot Control Panel** with real-time alerts
- ✅ **SQLite Database** for tracking targets, subdomains, and findings
- ✅ **Periodic Automated Scanning** with configurable intervals
- ✅ **Interactive Telegram Commands** for target management

## Prerequisites

### 1. Install Required Tools

```bash
# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest

# Or use package managers
# For Kali Linux:
sudo apt install subfinder dnsx httpx naabu nuclei katana dalfox gau waybackurls
```

### 2. Install Python Dependencies

```bash
pip install python-telegram-bot aiohttp
```

### 3. Setup Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow instructions to create your bot
4. Copy the bot token
5. Get your Telegram ID by messaging `@userinfobot`

### 4. Configure Environment Variables

```bash
export TELEGRAM_BOT_TOKEN='your_bot_token_here'
export TELEGRAM_ADMIN_ID='your_telegram_id_here'
```

## Usage

### Start the Watchtower

```bash
cd /workspace/sentinel_watchtower
python3 sentinel.py
```

### Telegram Bot Commands

| Command | Description |
|---------|-------------|
| `/start` | Show welcome message and help |
| `/add <domain>` | Add new target domain |
| `/targets` | List all active targets |
| `/scan <domain>` | Force immediate scan |
| `/stats` | Show statistics |
| `/findings` | View recent findings |
| `/pause <id>` | Pause scanning for target |
| `/resume <id>` | Resume scanning for target |
| `/remove <id>` | Remove target |
| `/help` | Show help message |

### Example Workflow

```bash
# Set environment variables
export TELEGRAM_BOT_TOKEN='1234567890:ABCdefGHIjklMNOpqrsTUVwxyz'
export TELEGRAM_ADMIN_ID='123456789'

# Start the watchtower
python3 sentinel.py

# In Telegram:
# Send: /add example.com
# The bot will immediately start scanning and notify you of findings
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Telegram Bot Interface                 │
│  (Commands, Alerts, Interactive Controls)               │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Sentinel Watchtower Core                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   Target     │  │    Scan      │  │   Alert      │  │
│  │   Manager    │  │  Orchestrator│  │   Handler    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Subdomain   │  │Vulnerability │  │   Crawl &    │
│  Discovery   │  │   Scanner    │  │  Discovery   │
│              │  │              │  │              │
│ • Subfinder  │  │ • Nuclei     │  │ • Katana     │
│ • Assetfinder│  │ • Dalfox     │  │ • Gau        │
│ • Findomain  │  │ • httpx      │  │ • Wayback    │
│ • DNSX       │  │ • naabu      │  │              │
└──────────────┘  └──────────────┘  └──────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                  SQLite Database                        │
│  • Targets                                              │
│  • Subdomains                                           │
│  • Findings                                             │
│  • Scan History                                         │
└─────────────────────────────────────────────────────────┘
```

## Scan Pipeline

1. **Subdomain Discovery**
   - Runs Subfinder, Assetfinder, Findomain
   - Resolves with DNSX
   - Stores new subdomains in database
   - Sends Telegram alert for new assets

2. **HTTP Probing**
   - Checks which subdomains have HTTP/HTTPS services
   - Collects status codes and titles

3. **Vulnerability Scanning**
   - Runs Nuclei templates on live hosts
   - Detects XSS with Dalfox
   - Stores findings with severity levels
   - Sends high-priority alerts for critical findings

4. **Endpoint Discovery**
   - Crawls with Katana
   - Fetches historical URLs with Gau/Wayback
   - Discovers hidden parameters and paths

## Database Schema

- **targets**: Domain targets with scan status
- **subdomains**: Discovered subdomains with IP addresses
- **findings**: Vulnerability findings with severity
- **scan_history**: Historical scan records

## Configuration

Edit `Config` class in `sentinel.py`:

```python
class Config:
    SCAN_INTERVAL_MINUTES = 30  # How often to scan each target
    MAX_CONCURRENT_SCANS = 3     # Maximum parallel scans
    DB_PATH = "db/sentinel.db"   # Database location
    LOGS_DIR = "logs"            # Log files directory
```

## Logs

- Main log: `logs/sentinel.log`
- Nuclei results: `logs/nuclei_*.json`

## Production Deployment

### Using systemd (Linux)

Create `/etc/systemd/system/sentinel-watchtower.service`:

```ini
[Unit]
Description=Sentinel Watchtower Bug Bounty Scanner
After=network.target

[Service]
Type=simple
User=your_user
WorkingDirectory=/workspace/sentinel_watchtower
Environment="TELEGRAM_BOT_TOKEN=your_token"
Environment="TELEGRAM_ADMIN_ID=your_id"
ExecStart=/usr/bin/python3 /workspace/sentinel_watchtower/sentinel.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable sentinel-watchtower
sudo systemctl start sentinel-watchtower
sudo systemctl status sentinel-watchtower
```

### Using Docker

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    curl git && \
    rm -rf /var/lib/apt/lists/*

# Install Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# ... add other tools

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python3", "sentinel.py"]
```

## Security Notes

⚠️ **IMPORTANT**: Only use this tool on targets you have explicit permission to test!

- Ensure you have written authorization for bug bounty programs
- Respect rate limits to avoid service disruption
- Review findings before reporting
- Follow responsible disclosure practices

## Troubleshooting

**Tools not found:**
```bash
# Verify installation
which subfinder dnsx httpx nuclei dalfox

# Add Go bin to PATH if needed
export PATH=$PATH:$(go env GOPATH)/bin
```

**Telegram bot not responding:**
- Check bot token is correct
- Verify admin ID matches your Telegram ID
- Ensure bot is not blocked

**Scan failures:**
- Check logs in `logs/sentinel.log`
- Verify target domains are valid
- Ensure network connectivity

## License

MIT License - Use responsibly and ethically only on authorized targets.

## Support

For issues and feature requests, check logs and verify tool installations.

Happy hunting! 🎯🛡️
