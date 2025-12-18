# Spiffy Security Tool - Enhanced Edition

## Quick Start

```bash
cd /Users/mg/Documents/spiffy
./run_security_tool.sh
```

Or manually:
```bash
source venv/bin/activate
python main_security_tool.py
```

## New Features

✅ **Password Policy Enforcement** - 12+ chars with complexity requirements  
✅ **Two-Factor Authentication** - TOTP-based 2FA with QR codes  
✅ **Database Security Auditing** - Permission checks on startup  
✅ **Suspicious Activity Detection** - Brute force and attack pattern analysis  
✅ **Input Sanitization** - SQL injection prevention  

## File Structure

- `security_utils.py` - Password policy, input sanitization, TOTP 2FA
- `db_auditor.py` - Database permission checks, log analysis
- `main_security_tool.py` - Main application (enhanced with 2FA)
- `test_security_modules.py` - Automated test suite (15/15 passing)

## Testing

Run automated tests:
```bash
source venv/bin/activate
python test_security_modules.py
```

## Documentation

See [walkthrough.md](file:///Users/mg/.gemini/antigravity/brain/00232dba-1af8-4098-adfb-96a2e17cfcb3/walkthrough.md) for complete documentation.
