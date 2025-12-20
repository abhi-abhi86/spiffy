#!/usr/bin/env python3
"""
Spiffy Web Chat Server
Flask + SocketIO for real-time browser-based chat
Accessible via public URL using ngrok
"""

from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import html
import uuid
from datetime import datetime

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'spiffy-ultron-chat-secret-key'

# Initialize SocketIO with CORS support
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Store active users: session_id -> {username, join_time}
active_users = {}

# Chat history (last 100 messages)
chat_history = []
MAX_HISTORY = 100


@app.route('/')
def index():
    """Serve the main chat page"""
    return render_template('chat.html')


@socketio.on('connect')
def handle_connect():
    """Handle new WebSocket connection"""
    print(f"[Server] New connection: {request.sid}")


@socketio.on('join')
def handle_join(data):
    """
    Handle user joining the chat
    - Sanitize username
    - Store user session
    - Broadcast join message
    - Send chat history
    """
    # Sanitize username
    username = html.escape(data.get('username', 'Anonymous')).strip()
    
    if not username:
        username = f"User_{request.sid[:8]}"
    
    # Store user
    active_users[request.sid] = {
        'username': username,
        'join_time': datetime.now().isoformat()
    }
    
    print(f"[Server] {username} joined (total users: {len(active_users)})")
    
    # Send chat history to new user
    emit('chat_history', {'messages': chat_history})
    
    # Broadcast join notification
    emit('user_joined', {
        'username': username,
        'user_count': len(active_users),
        'timestamp': datetime.now().isoformat()
    }, broadcast=True)
    
    # Send user list
    emit('user_list', {
        'users': [u['username'] for u in active_users.values()]
    }, broadcast=True)


@socketio.on('message')
def handle_message(data):
    """
    Handle incoming chat message
    - Sanitize message
    - Prevent empty messages
    - Broadcast to all users
    - Store in history
    """
    # Get username
    user_info = active_users.get(request.sid)
    if not user_info:
        return
    
    username = user_info['username']
    
    # Sanitize message
    message = html.escape(data.get('message', '')).strip()
    
    # Prevent empty messages
    if not message:
        return
    
    # Create message object
    msg_obj = {
        'username': username,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'session_id': request.sid[:8]
    }
    
    # Add to history
    chat_history.append(msg_obj)
    if len(chat_history) > MAX_HISTORY:
        chat_history.pop(0)
    
    print(f"[Server] {username}: {message}")
    
    # Broadcast message
    emit('message', msg_obj, broadcast=True)


@socketio.on('typing')
def handle_typing(data):
    """Handle typing indicator"""
    user_info = active_users.get(request.sid)
    if not user_info:
        return
    
    emit('user_typing', {
        'username': user_info['username'],
        'is_typing': data.get('is_typing', False)
    }, broadcast=True, include_self=False)


@socketio.on('disconnect')
def handle_disconnect():
    """
    Handle user disconnect
    - Remove from active users
    - Broadcast leave message
    """
    user_info = active_users.pop(request.sid, None)
    
    if user_info:
        username = user_info['username']
        print(f"[Server] {username} left (total users: {len(active_users)})")
        
        # Broadcast leave notification
        emit('user_left', {
            'username': username,
            'user_count': len(active_users),
            'timestamp': datetime.now().isoformat()
        }, broadcast=True)
        
        # Send updated user list
        emit('user_list', {
            'users': [u['username'] for u in active_users.values()]
        }, broadcast=True)


@app.route('/health')
def health():
    """Health check endpoint"""
    return {
        'status': 'ok',
        'active_users': len(active_users),
        'messages_in_history': len(chat_history)
    }


if __name__ == '__main__':
    print("="*60)
    print("  SPIFFY WEB CHAT SERVER")
    print("  Real-time browser-based chat")
    print("="*60)
    print("\nStarting server on http://localhost:5001")
    print("Use ngrok to create public URL")
    print("\nPress Ctrl+C to stop\n")
    
    # Run server (port 5001 to avoid macOS AirPlay on 5000)
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
