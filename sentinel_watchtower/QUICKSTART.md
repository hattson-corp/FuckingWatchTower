# Sentinel Watchtower - Quick Reference Guide

## 🚀 Setup (5 minutes)

### Step 1: Create Telegram Bot
1. Open Telegram, search for `@BotFather`
2. Send `/newbot`
3. Name your bot (e.g., "MyWatchtower")
4. Copy the token (looks like: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`)

### Step 2: Get Your Telegram ID
1. Search for `@userinfobot` in Telegram
2. Start a chat
3. It will show your ID (e.g., `123456789`)

### Step 3: Configure
```bash
cd /workspace/sentinel_watchtower
cp .env.example .env
nano .env  # Edit with your token and ID
```

### Step 4: Install Tools (Optional - automated)
```bash
./install.sh
```

### Step 5: Run
```bash
./start.sh
# OR manually:
export TELEGRAM_BOT_TOKEN='your_token'
export TELEGRAM_ADMIN_ID='your_id'
python3 sentinel.py
```

---

## 📱 Telegram Commands

| Command | Example | Description |
|---------|---------|-------------|
| `/start` | `/start` | Welcome message |
| `/add` | `/add example.com` | Add new target |
| `/targets` | `/targets` | List all targets |
| `/scan` | `/scan example.com` | Force scan now |
| `/stats` | `/stats` | View statistics |
| `/findings` | `/findings` | Recent findings |
| `/pause` | `/pause 1` | Pause target ID 1 |
| `/resume` | `/resume 1` | Resume target ID 1 |
| `/remove` | `/remove 1` | Remove target ID 1 |

---

## 🔍 What Gets Scanned

When you add a target, the watchtower automatically:

1. **Discovers Subdomains**
   - Uses Subfinder, Assetfinder, Findomain
   - Resolves IPs with DNSX
   - Alerts you when NEW subdomains are found

2. **Probes HTTP Services**
   - Checks which subdomains have websites
   - Collects status codes and titles

3. **Scans for Vulnerabilities**
   - Runs Nuclei templates (CVEs, misconfigurations, exposures)
   - Scans for XSS with Dalfox
   - Alerts on HIGH/CRITICAL findings

4. **Discovers Endpoints**
   - Crawls with Katana
   - Fetches historical URLs (Wayback, Gau)
   - Finds hidden paths and parameters

---

## 🎯 Example Workflow

```
You: /add tesla.com

Bot: ✅ Target added: tesla.com
     Scanning will begin automatically.

[2 minutes later]

Bot: 🟢ℹ️ Sentinel Alert
     
     **New Subdomains Found!**
     Target: tesla.com
     Total: 847
     New: 23

[10 minutes later]

Bot: 🟠⚠️ Sentinel Alert
     
     **Vulnerabilities Detected!**
     Target: tesla.com
     Nuclei Findings: 5
     Check /findings for details

You: /findings

Bot: [Shows detailed list of vulnerabilities with severity]
```

---

## 📊 Database Structure

All data is stored in `db/sentinel.db`:

- **targets**: Your target domains
- **subdomains**: All discovered subdomains with IPs
- **findings**: Vulnerability findings with severity
- **scan_history**: Historical scan records

View with:
```bash
sqlite3 db/sentinel.db "SELECT * FROM targets;"
sqlite3 db/sentinel.db "SELECT * FROM findings WHERE severity='high';"
```

---

## ⚙️ Configuration

Edit `sentinel.py` Config class:

```python
SCAN_INTERVAL_MINUTES = 30  # Scan frequency
MAX_CONCURRENT_SCANS = 3     # Parallel scans
```

---

## 🐛 Troubleshooting

### "Tools not found"
```bash
# Install missing tools
./install.sh

# Or manually add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

### "Bot not responding"
- Check bot token is correct
- Verify admin ID matches your Telegram ID
- Make sure bot isn't blocked

### "No findings showing"
- Run `/stats` to see if scans completed
- Check `logs/sentinel.log` for errors
- Try `/scan <domain>` to force a scan

---

## 🛡️ Production Deployment

### As a Systemd Service

```bash
sudo nano /etc/systemd/system/sentinel-watchtower.service
```

Paste:
```ini
[Unit]
Description=Sentinel Watchtower
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/workspace/sentinel_watchtower
Environment="TELEGRAM_BOT_TOKEN=your_token"
Environment="TELEGRAM_ADMIN_ID=your_id"
ExecStart=/usr/bin/python3 /workspace/sentinel_watchtower/sentinel.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinel-watchtower
sudo systemctl start sentinel-watchtower
sudo systemctl status sentinel-watchtower
```

---

## 📝 Tips for Bug Bounty

1. **Start small**: Add 1-2 targets first to test
2. **Monitor alerts**: Critical findings come instantly
3. **Review before reporting**: Always verify findings manually
4. **Respect rate limits**: Don't scan too aggressively
5. **Only authorized targets**: Stay within program scope

---

## 🎯 Sample Targets to Test

Try these (they have public bug bounty programs):
- `example.com` (safe for testing)
- Add your own test domain first

---

## 📞 Support

- Check logs: `tail -f logs/sentinel.log`
- Verify tools: `which subfinder dnsx httpx nuclei`
- Test database: `sqlite3 db/sentinel.db ".tables"`

Happy hunting! 🛡️🎯
