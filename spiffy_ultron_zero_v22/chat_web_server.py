#!/usr/bin/env python3
"""
Spiffy Private Chat - Web Server
MIT Licensed - Free to use and modify

Flask WebSocket server for browser clients
"""

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spiffy-private-chat-secret'
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active sessions
active_links = {}  # token -> {created, expires, active}
active_users = {}  # session_id -> {username, token, room}

@app.route('/')
def index():
    return "<h1>🔐 Spiffy Private Chat</h1><p>Use the host GUI to generate access links.</p>"

@app.route('/chat/<token>')
def chat(token):
    """Chat interface for users"""
    # Validate token (simplified - should check expiry, etc.)
    return render_template('chat_client.html', token=token)

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('join')
def handle_join(data):
    """User joins chat"""
    username = data.get('username', 'Anonymous')
    token = data.get('token', '')
    
    active_users[request.sid] = {
        'username': username,
        'token': token,
        'room': token
    }
    
    join_room(token)
    
    emit('user_joined', {
        'username': username,
        'timestamp': datetime.now().isoformat()
    }, room=token)
    
    print(f"{username} joined room {token[:16]}...")

@socketio.on('message')
def handle_message(data):
    """Handle chat message"""
    user = active_users.get(request.sid)
    if not user:
        return
    
    message_data = {
        'username': user['username'],
        'message': data.get('message', ''),
        'timestamp': datetime.now().isoformat()
    }
    
    emit('message', message_data, room=user['room'])
    print(f"{user['username']}: {message_data['message']}")

@socketio.on('disconnect')
def handle_disconnect():
    """User disconnects"""
    user = active_users.pop(request.sid, None)
    if user:
        leave_room(user['room'])
        emit('user_left', {
            'username': user['username'],
            'timestamp': datetime.now().isoformat()
        }, room=user['room'])
        print(f"{user['username']} left")

if __name__ == '__main__':
    print("="*60)
    print("  🔐 SPIFFY PRIVATE CHAT SERVER")
    print("  MIT Licensed - Free to use and modify")
    print("="*60)
    print("\n🌐 Server: http://localhost:5001")
    print("🎛️  Use the GUI to generate links\n")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
