# Spiffy Private Chat - Quick Start

## 🚀 **Quick Start**

### **1. Build (One Time)**
```bash
cd spiffy_ultron_zero_v22
./build_private_chat.sh
```

### **2. Run via spiffy_runner.sh**
```bash
./spiffy_runner.sh
# Select option [P] for Private Chat
```

### **3. Or Run Directly**
```bash
python3 private_chat_gui.py
```

---

## 🎨 **Features**

### **Host (You)**
- ✅ Beautiful PyQt6 desktop GUI
- ✅ Generate unique access links
- ✅ Monitor chat activity
- ✅ Revoke access anytime
- ✅ Gradient background, modern styling

### **Users (Browser)**
- ✅ Beautiful glassmorphism interface
- ✅ Real-time WebSocket messaging
- ✅ Smooth animations
- ✅ No installation needed
- ✅ Works on any device

### **Security (Rust Backend - 90%)**
- ✅ ChaCha20-Poly1305 encryption
- ✅ X25519 ECDH key exchange
- ✅ HMAC-SHA256 authentication
- ✅ HKDF key derivation
- ✅ End-to-end encrypted

---

## 📖 **How It Works**

### **Host Side:**
1. Click "🚀 Start Server"
2. Click "🔗 Generate Link"
3. Copy link (auto-copied to clipboard)
4. Share with users

### **User Side:**
1. Open link in browser
2. Enter username
3. Start chatting!

---

## 🏗️ **Architecture**

```
Rust (90%)          C++ (5%)           Python (5%)
├─ Encryption       ├─ TCP Sockets     ├─ PyQt6 GUI
├─ Key Exchange     └─ Connections     ├─ Flask Server
├─ Authentication                      └─ Browser Client
└─ Session Mgmt
```

---

## 📝 **MIT Licensed**

Free to use, modify, and distribute!

See `PRIVATE_CHAT_LICENSE.txt` for details.

---

## 🔧 **Requirements**

- Python 3.8+
- Rust (cargo)
- PyQt6
- Flask, Flask-SocketIO

All auto-installed by build script!

---

**Enjoy secure, beautiful, encrypted chat!** 🔐
