#!/usr/bin/env python3
"""
Sentinel Watchtower - Production-Ready Bug Bounty Automation System
Active subdomain discovery, vulnerability scanning, and Telegram alerting
"""

import os
import sys
import json
import time
import sqlite3
import asyncio
import logging
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional, Set
import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes

# Configuration
class Config:
    TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_ADMIN_ID = int(os.getenv("TELEGRAM_ADMIN_ID", "0"))
    DB_PATH = "db/sentinel.db"
    LOGS_DIR = "logs"
    WORDLISTS_DIR = "wordlists"
    SCAN_INTERVAL_MINUTES = 30
    MAX_CONCURRENT_SCANS = 3
    
    # Tool paths (adjust based on your installation)
    TOOLS = {
        "subfinder": "subfinder",
        "assetfinder": "assetfinder", 
        "findomain": "findomain",
        "dnsx": "dnsx",
        "naabu": "naabu",
        "httpx": "httpx",
        "tlsx": "tlsx",
        "katana": "katana",
        "nuclei": "nuclei",
        "dalfox": "dalfox",
        "sqlmap": "sqlmap",
        "arjun": "arjun",
        "gau": "gau",
        "waybackurls": "waybackurls",
        "ffuf": "ffuf",
        "gospider": "gospider"
    }

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'{Config.LOGS_DIR}/sentinel.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Database:
    """SQLite database manager for targets, findings, and scan history"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scan TIMESTAMP,
                scan_enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        # Subdomains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                subdomain TEXT NOT NULL,
                ip_address TEXT,
                status TEXT DEFAULT 'new',
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                UNIQUE(subdomain)
            )
        ''')
        
        # Findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                subdomain_id INTEGER,
                finding_type TEXT NOT NULL,
                severity TEXT,
                title TEXT,
                description TEXT,
                url TEXT,
                raw_output TEXT,
                status TEXT DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (target_id) REFERENCES targets(id),
                FOREIGN KEY (subdomain_id) REFERENCES subdomains(id)
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER,
                scan_type TEXT NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT,
                findings_count INTEGER DEFAULT 0,
                FOREIGN KEY (target_id) REFERENCES targets(id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def add_target(self, domain: str) -> bool:
        """Add a new target"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO targets (domain) VALUES (?)",
                (domain,)
            )
            conn.commit()
            success = cursor.rowcount > 0
            conn.close()
            return success
        except Exception as e:
            logger.error(f"Error adding target: {e}")
            return False
    
    def get_active_targets(self) -> List[Dict]:
        """Get all active targets"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM targets WHERE status='active' AND scan_enabled=1"
        )
        targets = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return targets
    
    def add_subdomain(self, target_id: int, subdomain: str, ip_address: str = None) -> bool:
        """Add or update subdomain"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if exists
            cursor.execute(
                "SELECT id FROM subdomains WHERE subdomain=?",
                (subdomain,)
            )
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute(
                    "UPDATE subdomains SET last_seen=CURRENT_TIMESTAMP, ip_address=? WHERE id=?",
                    (ip_address, existing[0])
                )
                is_new = False
            else:
                cursor.execute(
                    "INSERT INTO subdomains (target_id, subdomain, ip_address) VALUES (?, ?, ?)",
                    (target_id, subdomain, ip_address)
                )
                is_new = True
            
            conn.commit()
            conn.close()
            return is_new
        except Exception as e:
            logger.error(f"Error adding subdomain: {e}")
            return False
    
    def add_finding(self, target_id: int, subdomain_id: int, finding_type: str,
                   severity: str, title: str, description: str, url: str = None, raw_output: str = None) -> int:
        """Add a new finding"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO findings (target_id, subdomain_id, finding_type, severity, title, description, url, raw_output)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (target_id, subdomain_id, finding_type, severity, title, description, url, raw_output))
            finding_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return finding_id
        except Exception as e:
            logger.error(f"Error adding finding: {e}")
            return -1
    
    def log_scan(self, target_id: int, scan_type: str, status: str, findings_count: int = 0) -> int:
        """Log scan history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history (target_id, scan_type, start_time, end_time, status, findings_count)
                VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
            ''', (target_id, scan_type, status, findings_count))
            scan_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return scan_id
        except Exception as e:
            logger.error(f"Error logging scan: {e}")
            return -1
    
    def update_target_last_scan(self, target_id: int):
        """Update target's last scan timestamp"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE targets SET last_scan=CURRENT_TIMESTAMP WHERE id=?",
            (target_id,)
        )
        conn.commit()
        conn.close()

class ToolRunner:
    """Execute external security tools"""
    
    @staticmethod
    async def run_command(command: List[str], timeout: int = 300) -> tuple:
        """Run external command asynchronously"""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
                return process.returncode, stdout.decode(), stderr.decode()
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return -1, "", "Command timed out"
                
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return -1, "", str(e)
    
    @staticmethod
    def check_tool_installed(tool_name: str) -> bool:
        """Check if tool is installed"""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

class SubdomainScanner:
    """Active subdomain discovery module"""
    
    def __init__(self, db: Database):
        self.db = db
        self.tools = ToolRunner()
    
    async def discover_subdomains(self, domain: str) -> Set[str]:
        """Run multiple subdomain discovery tools"""
        all_subdomains = set()
        
        # Subfinder
        if self.tools.check_tool_installed(Config.TOOLS["subfinder"]):
            logger.info(f"Running subfinder on {domain}")
            returncode, stdout, stderr = await self.tools.run_command([
                Config.TOOLS["subfinder"], "-d", domain, "-silent"
            ])
            if returncode == 0:
                all_subdomains.update(stdout.strip().split('\n'))
        
        # Assetfinder
        if self.tools.check_tool_installed(Config.TOOLS["assetfinder"]):
            logger.info(f"Running assetfinder on {domain}")
            returncode, stdout, stderr = await self.tools.run_command([
                Config.TOOLS["assetfinder"], "--subs-only", domain
            ])
            if returncode == 0:
                all_subdomains.update(stdout.strip().split('\n'))
        
        # Findomain
        if self.tools.check_tool_installed(Config.TOOLS["findomain"]):
            logger.info(f"Running findomain on {domain}")
            returncode, stdout, stderr = await self.tools.run_command([
                Config.TOOLS["findomain"], "-t", domain, "-u", "-"
            ], timeout=120)
            # Findomain outputs to stdout in some versions
        
        # DNSX for resolution
        resolved_subdomains = set()
        if all_subdomains and self.tools.check_tool_installed(Config.TOOLS["dnsx"]):
            logger.info(f"Resolving subdomains with dnsx")
            input_data = '\n'.join(all_subdomains)
            process = await asyncio.create_subprocess_exec(
                Config.TOOLS["dnsx"], "-silent", "-resp",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate(input=input_data.encode())
            if process.returncode == 0:
                for line in stdout.decode().strip().split('\n'):
                    if line:
                        parts = line.split()
                        if len(parts) >= 2:
                            resolved_subdomains.add((parts[0], parts[1]))
        
        return all_subdomains, resolved_subdomains
    
    async def scan_target(self, target_id: int, domain: str) -> Dict:
        """Complete subdomain scan for a target"""
        logger.info(f"Starting subdomain scan for {domain}")
        
        # Discover subdomains
        all_subs, resolved_subs = await self.discover_subdomains(domain)
        
        new_count = 0
        for subdomain in all_subs:
            if not subdomain:
                continue
            ip = None
            if resolved_subs:
                for sub, ip_addr in resolved_subs:
                    if sub == subdomain:
                        ip = ip_addr
                        break
            
            is_new = self.db.add_subdomain(target_id, subdomain, ip)
            if is_new:
                new_count += 1
        
        # Log scan
        self.db.log_scan(target_id, "subdomain_discovery", "completed", new_count)
        self.db.update_target_last_scan(target_id)
        
        logger.info(f"Found {len(all_subs)} subdomains, {new_count} new for {domain}")
        return {"total": len(all_subs), "new": new_count}

class VulnerabilityScanner:
    """Vulnerability scanning module"""
    
    def __init__(self, db: Database):
        self.db = db
        self.tools = ToolRunner()
    
    async def http_probe(self, subdomains: List[str]) -> List[str]:
        """Probe subdomains for HTTP services"""
        if not subdomains or not self.tools.check_tool_installed(Config.TOOLS["httpx"]):
            return []
        
        input_data = '\n'.join(subdomains)
        process = await asyncio.create_subprocess_exec(
            Config.TOOLS["httpx"], "-silent", "-status-code", "-title",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate(input=input_data.encode())
        
        live_hosts = []
        if process.returncode == 0:
            for line in stdout.decode().strip().split('\n'):
                if line:
                    live_hosts.append(line)
        
        return live_hosts
    
    async def port_scan(self, subdomains: List[str]) -> Dict:
        """Scan ports on live hosts"""
        if not subdomains or not self.tools.check_tool_installed(Config.TOOLS["naabu"]):
            return {}
        
        input_data = '\n'.join(subdomains)
        process = await asyncio.create_subprocess_exec(
            Config.TOOLS["naabu"], "-silent", "-top-ports", "100",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await process.communicate(input=input_data.encode())
        
        open_ports = {}
        if process.returncode == 0:
            for line in stdout.decode().strip().split('\n'):
                if line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        host, port = parts
                        if host not in open_ports:
                            open_ports[host] = []
                        open_ports[host].append(port)
        
        return open_ports
    
    async def nuclei_scan(self, urls: List[str], target_id: int, subdomain_id: int = None) -> int:
        """Run Nuclei vulnerability scanner"""
        if not urls or not self.tools.check_tool_installed(Config.TOOLS["nuclei"]):
            return 0
        
        findings_count = 0
        input_data = '\n'.join(urls[:50])  # Limit to prevent timeout
        
        output_file = f"{Config.LOGS_DIR}/nuclei_{target_id}_{int(time.time())}.json"
        
        process = await asyncio.create_subprocess_exec(
            Config.TOOLS["nuclei"], "-silent", "-jsonl", output_file,
            "-u", ",".join(urls[:10]),  # Batch URLs
            timeout=600
        )
        await process.wait()
        
        # Parse results
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        result = json.loads(line)
                        severity = result.get('info', {}).get('severity', 'info')
                        title = result.get('info', {}).get('name', 'Unknown')
                        description = result.get('description', '')
                        url = result.get('matched-at', '')
                        
                        self.db.add_finding(
                            target_id=target_id,
                            subdomain_id=subdomain_id or 0,
                            finding_type="nuclei_vuln",
                            severity=severity,
                            title=title,
                            description=description[:500],
                            url=url
                        )
                        findings_count += 1
        except Exception as e:
            logger.error(f"Error parsing nuclei results: {e}")
        
        return findings_count
    
    async def xss_scan(self, urls: List[str], target_id: int) -> int:
        """Scan for XSS vulnerabilities"""
        if not urls or not self.tools.check_tool_installed(Config.TOOLS["dalfox"]):
            return 0
        
        findings_count = 0
        for url in urls[:20]:  # Limit URLs
            if '?' in url:  # Only scan URLs with parameters
                process = await asyncio.create_subprocess_exec(
                    Config.TOOLS["dalfox"], "url", url, "--format", "json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                try:
                    results = json.loads(stdout.decode())
                    for result in results:
                        if result.get('type') == 'R':
                            self.db.add_finding(
                                target_id=target_id,
                                subdomain_id=0,
                                finding_type="xss",
                                severity="high",
                                title="Reflected XSS",
                                description=f"XSS found in parameter: {result.get('poc', '')}",
                                url=url
                            )
                            findings_count += 1
                except Exception:
                    pass
        
        return findings_count
    
    async def crawl_and_discover(self, domain: str) -> List[str]:
        """Crawl website and discover endpoints"""
        endpoints = []
        
        if self.tools.check_tool_installed(Config.TOOLS["katana"]):
            process = await asyncio.create_subprocess_exec(
                Config.TOOLS["katana"], "-list", domain, "-f", "url", "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                timeout=300
            )
            stdout, _ = await process.communicate()
            if process.returncode == 0:
                endpoints = stdout.decode().strip().split('\n')
        
        # Also use gau for historical URLs
        if self.tools.check_tool_installed(Config.TOOLS["gau"]):
            process = await asyncio.create_subprocess_exec(
                Config.TOOLS["gau"], domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                timeout=180
            )
            stdout, _ = await process.communicate()
            if process.returncode == 0:
                endpoints.extend(stdout.decode().strip().split('\n'))
        
        return list(set(endpoints))

class TelegramBot:
    """Telegram bot for control and alerts"""
    
    def __init__(self, watchtower):
        self.watchtower = watchtower
        self.db = watchtower.db
        self.app = None
    
    def create_app(self) -> Application:
        """Create Telegram bot application"""
        app = Application.builder().token(Config.TELEGRAM_BOT_TOKEN).build()
        
        # Command handlers
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("add", self.cmd_add_target))
        app.add_handler(CommandHandler("targets", self.cmd_list_targets))
        app.add_handler(CommandHandler("scan", self.cmd_scan_now))
        app.add_handler(CommandHandler("stats", self.cmd_stats))
        app.add_handler(CommandHandler("help", self.cmd_help))
        app.add_handler(CommandHandler("pause", self.cmd_pause_target))
        app.add_handler(CommandHandler("resume", self.cmd_resume_target))
        app.add_handler(CommandHandler("remove", self.cmd_remove_target))
        app.add_handler(CommandHandler("findings", self.cmd_recent_findings))
        
        # Callback handler for inline buttons
        app.add_handler(CallbackQueryHandler(self.callback_handler))
        
        return app
    
    async def cmd_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start command"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            await update.message.reply_text("Unauthorized access.")
            return
        
        welcome_text = """
🛡️ **Sentinel Watchtower** 🛡️

*Status:* Active
*Targets:* Monitoring enabled

*Commands:*
/add <domain> - Add new target
/targets - List all targets
/scan <domain> - Force scan now
/stats - Show statistics
/findings - Recent findings
/pause <id> - Pause scanning
/resume <id> - Resume scanning
/remove <id> - Remove target
/help - Show this help

Ready to hunt! 🎯
        """
        await update.message.reply_text(welcome_text, parse_mode='Markdown')
    
    async def cmd_add_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Add new target"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /add <domain.com>")
            return
        
        domain = context.args[0].lower()
        if self.db.add_target(domain):
            await update.message.reply_text(f"✅ Target added: {domain}\nScanning will begin automatically.")
            # Trigger immediate scan
            asyncio.create_task(self.watchtower.scan_target_by_domain(domain))
        else:
            await update.message.reply_text(f"⚠️ Target already exists or error adding: {domain}")
    
    async def cmd_list_targets(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """List all targets"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            return
        
        targets = self.db.get_active_targets()
        if not targets:
            await update.message.reply_text("No active targets.")
            return
        
        text = "📋 **Active Targets:**\n\n"
        keyboard = []
        
        for i, target in enumerate(targets):
            last_scan = target['last_scan'] or 'Never'
            status = "🟢" if target['scan_enabled'] else "🔴"
            text += f"{status} `{target['id']}`. {target['domain']}\n   Last: {last_scan}\n"
            keyboard.append([InlineKeyboardButton(
                f"{'⏸️' if target['scan_enabled'] else '▶️'} {target['domain']}",
                callback_data=f"toggle_{target['id']}"
            )])
        
        keyboard.append([InlineKeyboardButton("🔄 Refresh", callback_data="refresh_targets")])
        
        await update.message.reply_text(
            text,
            parse_mode='Markdown',
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    async def cmd_scan_now(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Force scan a target"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            return
        
        if not context.args:
            await update.message.reply_text("Usage: /scan <domain>")
            return
        
        domain = context.args[0].lower()
        await update.message.reply_text(f"🔍 Starting immediate scan for {domain}...")
        asyncio.create_task(self.watchtower.scan_target_by_domain(domain))
    
    async def cmd_stats(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show statistics"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            return
        
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM targets")
        total_targets = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM subdomains")
        total_subdomains = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM findings WHERE status='new'")
        new_findings = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]
        
        cursor.execute("""
            SELECT severity, COUNT(*) 
            FROM findings 
            GROUP BY severity
        """)
        severity_counts = cursor.fetchall()
        
        conn.close()
        
        stats_text = f"""
📊 **Watchtower Statistics**

🎯 Total Targets: {total_targets}
🌐 Total Subdomains: {total_subdomains}
⚠️ New Findings: {new_findings}
📈 Total Findings: {total_findings}

**By Severity:**
"""
        for severity, count in severity_counts:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(severity, "•")
            stats_text += f"{emoji} {severity.capitalize()}: {count}\n"
        
        await update.message.reply_text(stats_text, parse_mode='Markdown')
    
    async def cmd_recent_findings(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show recent findings"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID:
            return
        
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT f.*, t.domain, s.subdomain
            FROM findings f
            JOIN targets t ON f.target_id = t.id
            LEFT JOIN subdomains s ON f.subdomain_id = s.id
            WHERE f.status = 'new'
            ORDER BY f.created_at DESC
            LIMIT 10
        """)
        
        findings = cursor.fetchall()
        conn.close()
        
        if not findings:
            await update.message.reply_text("No new findings.")
            return
        
        for finding in findings:
            severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                finding['severity'], "ℹ️"
            )
            
            text = f"""
{severity_emoji} **{finding['title']}**
Severity: {finding['severity'].upper()}
Target: {finding['domain']}
Subdomain: {finding['subdomain'] or 'N/A'}
Type: {finding['finding_type']}
URL: `{finding['url'] or 'N/A'}`

{finding['description'][:200]}...
            """
            
            keyboard = [[
                InlineKeyboardButton("✅ Mark Read", callback_data=f"read_{finding['id']}"),
                InlineKeyboardButton("🔍 Details", callback_data=f"detail_{finding['id']}")
            ]]
            
            await update.message.reply_text(text, parse_mode='Markdown', reply_markup=InlineKeyboardMarkup(keyboard))
    
    async def cmd_help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show help"""
        await self.cmd_start(update, context)
    
    async def cmd_pause_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Pause target scanning"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID or not context.args:
            return
        
        target_id = int(context.args[0])
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE targets SET scan_enabled=0 WHERE id=?", (target_id,))
        conn.commit()
        conn.close()
        
        await update.message.reply_text(f"⏸️ Scanning paused for target ID {target_id}")
    
    async def cmd_resume_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Resume target scanning"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID or not context.args:
            return
        
        target_id = int(context.args[0])
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE targets SET scan_enabled=1 WHERE id=?", (target_id,))
        conn.commit()
        conn.close()
        
        await update.message.reply_text(f"▶️ Scanning resumed for target ID {target_id}")
    
    async def cmd_remove_target(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Remove target"""
        if update.effective_user.id != Config.TELEGRAM_ADMIN_ID or not context.args:
            return
        
        target_id = int(context.args[0])
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM targets WHERE id=?", (target_id,))
        conn.commit()
        conn.close()
        
        await update.message.reply_text(f"🗑️ Target ID {target_id} removed")
    
    async def callback_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle inline button callbacks"""
        query = update.callback_query
        data = query.data
        
        if data.startswith("toggle_"):
            target_id = int(data.split("_")[1])
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT scan_enabled FROM targets WHERE id=?", (target_id,))
            result = cursor.fetchone()
            if result:
                new_status = 0 if result[0] else 1
                cursor.execute("UPDATE targets SET scan_enabled=? WHERE id=?", (new_status, target_id))
                conn.commit()
                await query.answer(f"Scanning {'paused' if new_status == 0 else 'resumed'}")
            conn.close()
        
        elif data.startswith("read_"):
            finding_id = int(data.split("_")[1])
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            cursor.execute("UPDATE findings SET status='read' WHERE id=?", (finding_id,))
            conn.commit()
            conn.close()
            await query.answer("✅ Marked as read")
        
        elif data == "refresh_targets":
            await query.answer("Refreshing...")
            await self.cmd_list_targets(update, context)
        
        await query.edit_message_reply_markup(reply_markup=None)
    
    async def send_alert(self, message: str, priority: str = "medium"):
        """Send alert to Telegram"""
        if not self.app:
            return
        
        severity_emoji = {
            "critical": "🔴🚨",
            "high": "🟠⚠️",
            "medium": "🟡⚡",
            "low": "🟢ℹ️",
            "info": "ℹ️"
        }.get(priority, "📢")
        
        full_message = f"{severity_emoji} **Sentinel Alert**\n\n{message}"
        
        try:
            await self.app.bot.send_message(
                chat_id=Config.TELEGRAM_ADMIN_ID,
                text=full_message,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")

class SentinelWatchtower:
    """Main watchtower orchestrator"""
    
    def __init__(self):
        self.db = Database(Config.DB_PATH)
        self.subdomain_scanner = SubdomainScanner(self.db)
        self.vuln_scanner = VulnerabilityScanner(self.db)
        self.telegram_bot = TelegramBot(self)
        self.running = False
    
    async def scan_target_by_domain(self, domain: str):
        """Scan a specific target by domain name"""
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM targets WHERE domain=?", (domain,))
        target = cursor.fetchone()
        conn.close()
        
        if target:
            await self.scan_target(dict(target))
        else:
            logger.warning(f"Target {domain} not found")
    
    async def scan_target(self, target: Dict):
        """Execute full scan pipeline for a target"""
        target_id = target['id']
        domain = target['domain']
        
        logger.info(f"Starting full scan for {domain}")
        
        try:
            # Phase 1: Subdomain Discovery
            sub_result = await self.subdomain_scanner.scan_target(target_id, domain)
            
            if sub_result['new'] > 0:
                await self.telegram_bot.send_alert(
                    f"**New Subdomains Found!**\n"
                    f"Target: {domain}\n"
                    f"Total: {sub_result['total']}\n"
                    f"New: {sub_result['new']}",
                    priority="info"
                )
            
            # Get subdomains for further scanning
            conn = sqlite3.connect(self.db.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT subdomain FROM subdomains WHERE target_id=?", (target_id,))
            subdomains = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            # Phase 2: HTTP Probing
            live_hosts = await self.vuln_scanner.http_probe(subdomains)
            
            if live_hosts:
                # Convert to URLs
                urls = [f"http://{host}" if not host.startswith('http') else host 
                       for host in live_hosts[:50]]
                
                # Phase 3: Nuclei Vulnerability Scan
                nuclei_findings = await self.vuln_scanner.nuclei_scan(urls, target_id)
                
                if nuclei_findings > 0:
                    await self.telegram_bot.send_alert(
                        f"**Vulnerabilities Detected!**\n"
                        f"Target: {domain}\n"
                        f"Nuclei Findings: {nuclei_findings}\n"
                        f"Check /findings for details",
                        priority="high"
                    )
                
                # Phase 4: XSS Scanning
                xss_findings = await self.vuln_scanner.xss_scan(urls, target_id)
                
                if xss_findings > 0:
                    await self.telegram_bot.send_alert(
                        f"**XSS Vulnerabilities Found!**\n"
                        f"Target: {domain}\n"
                        f"XSS Count: {xss_findings}",
                        priority="critical"
                    )
                
                # Phase 5: Crawl for more endpoints
                endpoints = await self.vuln_scanner.crawl_and_discover(domain)
                logger.info(f"Discovered {len(endpoints)} endpoints for {domain}")
            
            logger.info(f"Scan completed for {domain}")
            
        except Exception as e:
            logger.error(f"Scan failed for {domain}: {e}")
            self.db.log_scan(target_id, "full_scan", "failed")
    
    async def run_periodic_scans(self):
        """Run periodic scans on all active targets"""
        while self.running:
            targets = self.db.get_active_targets()
            
            for target in targets:
                # Check if enough time has passed since last scan
                if target['last_scan']:
                    last_scan = datetime.strptime(target['last_scan'], '%Y-%m-%d %H:%M:%S')
                    if datetime.now() - last_scan < timedelta(minutes=Config.SCAN_INTERVAL_MINUTES):
                        continue
                
                await self.scan_target(target)
                await asyncio.sleep(60)  # Delay between targets
            
            await asyncio.sleep(60)
    
    async def start(self):
        """Start the watchtower"""
        if not Config.TELEGRAM_BOT_TOKEN:
            logger.error("TELEGRAM_BOT_TOKEN not set. Please set environment variable.")
            print("\n❌ Error: TELEGRAM_BOT_TOKEN environment variable not set!")
            print("Set it with: export TELEGRAM_BOT_TOKEN='your_bot_token'")
            print("And: export TELEGRAM_ADMIN_ID='your_telegram_id'\n")
            return
        
        self.running = True
        
        # Create Telegram bot
        self.telegram_bot.app = self.telegram_bot.create_app()
        
        # Start bot
        await self.telegram_bot.app.initialize()
        await self.telegram_bot.app.start()
        
        updater = self.telegram_bot.app.updater
        await updater.start_polling()
        
        logger.info("Sentinel Watchtower started!")
        await self.telegram_bot.send_alert("🛡️ **Sentinel Watchtower Online!**\nMonitoring active.", "info")
        
        # Run periodic scans
        await self.run_periodic_scans()
    
    async def stop(self):
        """Stop the watchtower"""
        self.running = False
        if self.telegram_bot.app:
            await self.telegram_bot.app.stop()
        logger.info("Sentinel Watchtower stopped")

async def main():
    """Main entry point"""
    watchtower = SentinelWatchtower()
    
    try:
        await watchtower.start()
    except KeyboardInterrupt:
        await watchtower.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
