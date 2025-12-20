# Ngrok Setup Guide for Spiffy Chat

## 🚀 Quick Setup (2 Minutes)

### Step 1: Get Ngrok Account (FREE)

1. **Open browser**: https://dashboard.ngrok.com/signup
2. **Sign up** with Google/GitHub (fastest) or email
3. **Done!** Account created

### Step 2: Get Your Authtoken

1. **After signup**, you'll see your authtoken
2. **Or visit**: https://dashboard.ngrok.com/get-started/your-authtoken
3. **Copy** the token (looks like: `2abc...xyz`)

### Step 3: Configure Ngrok

**Option A - Automated (Recommended):**
```bash
cd /Users/mg/Documents/spiffy/spiffy_ultron_zero_v22
./setup_ngrok.sh
# Paste your token when prompted
```

**Option B - Manual:**
```bash
ngrok config add-authtoken YOUR_TOKEN_HERE
```

### Step 4: Start Tunnel

```bash
ngrok http 5001
```

You'll see:
```
Forwarding  https://abc123.ngrok.io -> http://localhost:5001
```

**Share the https://abc123.ngrok.io URL!**

---

## ✅ Complete Flow

```bash
# Terminal 1 - Server (already running)
cd spiffy_ultron_zero_v22
python3 chat_server.py
# Server on http://localhost:5001 ✓

# Terminal 2 - Ngrok
./setup_ngrok.sh
# Enter token when prompted
# Public URL: https://abc123.ngrok.io ✓

# Share URL with friends!
```

---

## 🎯 What You Get

- ✅ **Public HTTPS URL** (https://abc123.ngrok.io)
- ✅ **Works anywhere** (different networks, countries)
- ✅ **Free forever** (basic plan)
- ✅ **No installation** needed for users
- ✅ **Just share link** → they chat!

---

## 🔧 Troubleshooting

### "Authentication failed"
- Get new token: https://dashboard.ngrok.com/get-started/your-authtoken
- Run: `ngrok config add-authtoken YOUR_NEW_TOKEN`

### "Tunnel not found"
- Wait 5 seconds after starting ngrok
- Check: http://localhost:4040

### "Connection refused"
- Make sure server is running: `python3 chat_server.py`
- Check: http://localhost:5001

---

## 📱 Example Usage

**You:**
```bash
./setup_ngrok.sh
# Public URL: https://abc123.ngrok.io
```

**Friend (Phone):**
```
Opens Chrome
Pastes: https://abc123.ngrok.io
Enters username: "Alice"
Chats! ✓
```

**Friend (Computer):**
```
Opens Firefox
Pastes: https://abc123.ngrok.io  
Enters username: "Bob"
Chats! ✓
```

---

**Setup once, use forever!** 🎉
