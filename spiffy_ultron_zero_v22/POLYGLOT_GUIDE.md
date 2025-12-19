# Omega Kernel - Polyglot Enhancement

## Quick Start Guide

### PHP Web Dashboard

**Start the dashboard:**
```bash
cd spiffy_ultron_zero_v22/php_dashboard
php -S localhost:8080
```

**Access in browser:**
```
http://localhost:8080
```

**Features:**
- Real-time audit log viewing
- Filter by module and severity
- Statistics dashboard
- Auto-refresh every 30 seconds
- REST API at `/api/findings.php`

### Ruby Automation

**Run daily scan:**
```bash
cd spiffy_ultron_zero_v22/ruby_automation
ruby workflows/daily_scan.rb
```

**Create custom workflow:**
```ruby
require_relative 'omega_dsl'

Omega.workflow("My Custom Scan") do
  scan "192.168.1.0/24"
  report format: :json
  alert("Scan complete!")
end
```

### REST API Examples

**Get all findings:**
```bash
curl "http://localhost:8080/api/findings.php?action=findings&limit=10"
```

**Get statistics:**
```bash
curl "http://localhost:8080/api/findings.php?action=stats"
```

**Get modules:**
```bash
curl "http://localhost:8080/api/findings.php?action=modules"
```

## Architecture

```
Omega Kernel (Polyglot)
├── Python Core (Main Engine)
│   ├── spiffy.py
│   ├── omega_logger.py
│   ├── performance_monitor.py
│   └── error_handler.py
├── PHP Dashboard (Web Interface)
│   ├── index.php
│   └── api/findings.php
└── Ruby Automation (Workflows)
    ├── omega_dsl.rb
    └── workflows/daily_scan.rb
```

## Integration

All three languages share the same SQLite database (`ultron_zero.db`):
- **Python**: Writes scan results and logs
- **PHP**: Reads and displays via web interface
- **Ruby**: Reads for automation and writes reports
