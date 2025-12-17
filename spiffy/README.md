# Spiffy Secure Chat

A terminal-based encrypted chat application with TLS and AES-GCM security.

## Features

- **End-to-End Encryption**: AES-GCM authenticated encryption
- **Transport Security**: TLS/SSL for all communications
- **Replay Protection**: Nonce-based message replay prevention
- **Thread-Safe**: Concurrent client handling
- **Terminal UI**: Matrix-style interface with animations

## Security

- 256-bit cryptographically secure keys
- TLS 1.2+ with self-signed certificates (demo)
- Challenge-response authentication
- Input validation and sanitization

## Installation

1. Clone the repository
2. Create virtual environment: `python3 -m venv venv`
3. Activate: `source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Generate certificates: `openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"`

## Usage

### Server
```bash
python3 spiffy.py
# Choose option 1: Initialize Server Node
# Note the displayed secure channel key
```

### Client
```bash
python3 spiffy.py
# Choose option 2: Connect to Uplink
# Enter server IP (e.g., 192.168.1.100)
# Enter port (default 5555)
# Enter the secure channel key from server
# Enter your callsign/username
```

## Commands

- `/dm <user> <message>` - Send private message
- `/clear` - Clear terminal
- `/panic` - Fake system update screen
- `/help` - Show commands
- `/quit` - Exit

## Network Setup

For network access:
- Server binds to 0.0.0.0 by default
- Ensure firewall allows port 5555
- For internet access, configure port forwarding

## Security Notes

- Uses self-signed certificates for demo
- In production, use CA-signed certificates
- Keys are generated per session
- All traffic is encrypted and authenticated

## Testing

Run crypto tests: `python3 test_security.py`. 


# RUN

To run : `source venv/bin/activate && echo "1" | python spiffy/spiffy.py` or `python spiffy.py`