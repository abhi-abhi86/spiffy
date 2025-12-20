# New Features: Real Packet Sniffing & Scheduled Scans

## 🎉 What's New

This update adds two major features to the Spiffy/Ultron security suite:

1. **Real Packet Sniffing** - Actual network traffic capture and analysis using Scapy
2. **Scheduled Scans** - Automated security scans with cron-like scheduling
3. **Multi-Channel Notifications** - Email, Telegram, and Discord alerts

---

## 📦 Installation

### Install New Dependencies

```bash
cd /Users/mg/Documents/spiffy/spiffy_ultron_zero_v22
pip install -r ../requirements.txt
```

**New packages:**
- `scapy>=2.5.0` - Packet capture and analysis
- `APScheduler>=3.10.0` - Job scheduling
- `requests>=2.31.0` - HTTP requests for webhooks

---

## 🔍 1. Real Packet Sniffing

### Features
- Live packet capture on any network interface
- Protocol detection (TCP, UDP, ICMP, HTTP, DNS, ARP)
- Threat detection (port scans, ARP spoofing)
- Packet statistics and flow analysis
- Optional PCAP export

### Usage

**From Main Application:**
```bash
python3 spiffy.py
# Select [B] PACKET_SNIFFER from menu
```

**Standalone CLI:**
```bash
# Requires root/sudo privileges
sudo python3 packet_analyzer.py -i en0 -t 30

# With BPF filter
sudo python3 packet_analyzer.py -i en0 -t 60 -f "tcp port 80"

# Save to PCAP
sudo python3 packet_analyzer.py -i en0 -t 30 -o capture.pcap

# JSON output
sudo python3 packet_analyzer.py -i en0 -t 30 --json
```

**Via Bash Wrapper:**
```bash
sudo ./omega_ops.sh sniff en0
```

### Important Notes
- **Requires root/sudo** for packet capture
- Automatically falls back to simulation if Scapy not installed
- Legal warning: Only use on networks you own or have permission to monitor

---

## ⏰ 2. Scheduled Scans

### Features
- Cron-like scheduling (e.g., `0 2 * * *` for 2 AM daily)
- Interval scheduling (e.g., `1h`, `30m`, `2d`)
- Job management (add, list, pause, resume, delete)
- Persistent storage (survives restarts)
- Execution history tracking

### Usage

**From Main Application:**
```bash
python3 spiffy.py
# Select [S] SCHEDULER from menu
# Choose: [1] List Jobs, [2] Add Job, [3] Remove Job, [4] Pause/Resume
```

**Standalone CLI:**
```bash
# List all jobs
python3 scheduler.py list

# Add a job
python3 scheduler.py add "Daily Scan" WIFI_RADAR "0 2 * * *" --notify email telegram

# Remove a job
python3 scheduler.py remove "Daily Scan"

# Pause/Resume
python3 scheduler.py pause "Daily Scan"
python3 scheduler.py resume "Daily Scan"

# View execution history
python3 scheduler.py history --job "Daily Scan" --limit 20

# Start scheduler daemon
python3 scheduler.py start
```

**Via Bash Wrapper:**
```bash
# List jobs
./omega_ops.sh schedule list

# Add job (interactive)
./omega_ops.sh schedule add
```

### Schedule Examples

**Cron Format:**
- `0 2 * * *` - Every day at 2 AM
- `0 */6 * * *` - Every 6 hours
- `0 0 * * 0` - Every Sunday at midnight
- `30 14 * * 1-5` - Weekdays at 2:30 PM

**Interval Format:**
- `1h` - Every hour
- `30m` - Every 30 minutes
- `2d` - Every 2 days
- `15s` - Every 15 seconds

### Configuration File

Jobs are stored in `scan_schedule.json`:
```json
{
  "jobs": {
    "Daily Network Scan": {
      "module": "WIFI_RADAR",
      "schedule": "0 2 * * *",
      "enabled": true,
      "notify_channels": ["email", "telegram"]
    }
  }
}
```

---

## 📢 3. Notifications

### Supported Channels
- **Email** (SMTP) - Gmail, Outlook, custom SMTP servers
- **Telegram** - Bot API
- **Discord** - Webhooks

### Setup

**1. Copy Example Config:**
```bash
cp notifications.conf.example notifications.conf
```

**2. Edit Configuration:**
```bash
nano notifications.conf
```

**3. Configure Each Channel:**

#### Email (Gmail Example)
```ini
[email]
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
from_email = your_email@gmail.com
to_email = recipient@example.com
password = your_app_password  # Use App Password, not regular password
```

**Get Gmail App Password:** https://support.google.com/accounts/answer/185833

#### Telegram
```ini
[telegram]
enabled = true
bot_token = 123456789:ABCdefGHIjklMNOpqrsTUVwxyz  # From @BotFather
chat_id = 987654321  # From @userinfobot
```

**Setup Steps:**
1. Message @BotFather on Telegram → `/newbot`
2. Get your `bot_token`
3. Message @userinfobot → Get your `chat_id`

#### Discord
```ini
[discord]
enabled = true
webhook_url = https://discord.com/api/webhooks/...
```

**Setup Steps:**
1. Server Settings → Integrations → Webhooks
2. Create webhook → Copy URL

### Usage

**From Main Application:**
```bash
python3 spiffy.py
# Select [N] NOTIFICATIONS from menu
# Choose: [1] Show Status, [2] Test Notifications, [3] Configure
```

**Standalone CLI:**
```bash
# Show status
python3 notifier.py --status

# Test all channels
python3 notifier.py --test

# Test specific channel
python3 notifier.py --test-email
python3 notifier.py --test-telegram
python3 notifier.py --test-discord

# Send custom notification
python3 notifier.py --send "Test Alert" "This is a test message" --channels email telegram
```

**Via Bash Wrapper:**
```bash
# Show status
./omega_ops.sh notify status

# Test notifications
./omega_ops.sh notify test
```

---

## 🔗 Integration Example

**Complete Workflow:**

1. **Configure Notifications:**
```bash
python3 notifier.py --status  # Check config
python3 notifier.py --test    # Test channels
```

2. **Schedule Automated Scans:**
```bash
python3 scheduler.py add "Nightly Scan" WIFI_RADAR "0 2 * * *" --notify email telegram
python3 scheduler.py add "Hourly Vuln Check" VULN_SCANNER "1h" --notify discord
```

3. **Start Scheduler Daemon:**
```bash
python3 scheduler.py start
# Or run in background:
nohup python3 scheduler.py start > scheduler.log 2>&1 &
```

4. **Monitor:**
```bash
python3 scheduler.py list
python3 scheduler.py history
```

---

## 🧪 Testing

### Test Packet Sniffing
```bash
# Quick 10-second capture
sudo python3 packet_analyzer.py -i en0 -t 10

# Should show:
# - Protocol breakdown (TCP, UDP, etc.)
# - Top connections
# - DNS queries
# - Any detected threats
```

### Test Scheduler
```bash
# Add a test job for 1 minute from now
python3 scheduler.py add "Test Job" WIFI_RADAR "1m"
python3 scheduler.py list

# Wait 1 minute, check history
python3 scheduler.py history
```

### Test Notifications
```bash
# Test all configured channels
python3 notifier.py --test

# Should receive test messages on all enabled channels
```

---

## 📝 Troubleshooting

### Packet Sniffing Issues

**"Permission denied"**
```bash
# Run with sudo
sudo python3 packet_analyzer.py -i en0 -t 30
```

**"Scapy not installed"**
```bash
pip install scapy
```

**"No packets captured"**
- Check interface name: `ifconfig` or `ip addr`
- Try different interface (e.g., `wlan0`, `eth0`)
- Check BPF filter syntax

### Scheduler Issues

**"APScheduler not installed"**
```bash
pip install APScheduler
```

**Jobs not running**
- Check `scan_schedule.json` - jobs should have `"enabled": true`
- Verify scheduler daemon is running
- Check execution history for errors

### Notification Issues

**Email not sending**
- Use App Password, not regular password (for Gmail)
- Check SMTP server and port
- Verify firewall allows SMTP traffic

**Telegram not working**
- Verify bot token is correct
- Check chat_id (message @userinfobot)
- Ensure bot was started (send `/start` to your bot)

**Discord not working**
- Verify webhook URL is complete
- Check webhook hasn't been deleted
- Ensure webhook has permissions

---

## 🎯 Quick Reference

### Main Application Menu
- `[B]` - Packet Sniffer (Real capture)
- `[S]` - Scheduler Management
- `[N]` - Notification Settings

### Bash Commands
```bash
./omega_ops.sh sniff [interface]     # Packet capture
./omega_ops.sh schedule list         # List jobs
./omega_ops.sh schedule add          # Add job
./omega_ops.sh notify status         # Notification status
./omega_ops.sh notify test           # Test notifications
```

### Python Modules
```bash
python3 packet_analyzer.py --help
python3 scheduler.py --help
python3 notifier.py --help
```

---

## 📚 Additional Resources

- **Scapy Documentation:** https://scapy.readthedocs.io/
- **APScheduler Documentation:** https://apscheduler.readthedocs.io/
- **Cron Expression Generator:** https://crontab.guru/
- **Gmail App Passwords:** https://support.google.com/accounts/answer/185833
- **Telegram Bot API:** https://core.telegram.org/bots/api
- **Discord Webhooks:** https://discord.com/developers/docs/resources/webhook

---

## ⚠️ Legal & Security Notes

1. **Packet Sniffing:** Only monitor networks you own or have explicit permission to analyze
2. **Scheduled Scans:** Be mindful of scan frequency to avoid network disruption
3. **Credentials:** Never commit `notifications.conf` to git (it's in `.gitignore`)
4. **Notifications:** Sensitive scan results may be sent via notifications - use secure channels

---

**Enjoy the new features! 🚀**
