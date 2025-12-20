#!/usr/bin/env python3
"""
Spiffy Private Chat - Web-Based Host Dashboard
MIT Licensed - Free to use and modify

Enhanced with: Reply, Image Upload, Member List
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
import secrets
from datetime import datetime, timedelta
import webbrowser
import threading
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spiffy-private-chat-secret'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
socketio = SocketIO(app, cors_allowed_origins="*")

# Store active sessions
active_links = {}
active_users = {}
chat_messages = []

# Create uploads folder
os.makedirs('static/uploads', exist_ok=True)

@app.route('/')
def host_dashboard():
    """Beautiful host dashboard"""
    return render_template('host_dashboard.html')

@app.route('/chat/<token>')
def chat(token):
    """Chat interface for users"""
    return render_template('chat_client.html', token=token)

@app.route('/api/generate_link', methods=['POST'])
def generate_link():
    """Generate new access link"""
    token = secrets.token_urlsafe(32)
    created = datetime.now()
    expires = created + timedelta(hours=24)
    
    # Get network IP address
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except:
        local_ip = "localhost"
    
    url = f"http://{local_ip}:5001/chat/{token}"
    
    active_links[token] = {
        'token': token,
        'url': url,
        'created': created.isoformat(),
        'expires': expires.isoformat(),
        'active': True
    }
    
    return jsonify({
        'success': True,
        'token': token,
        'url': url,
        'created': created.isoformat(),
        'expires': expires.isoformat()
    })

@app.route('/api/links', methods=['GET'])
def get_links():
    """Get all active links"""
    links = []
    for token, data in active_links.items():
        links.append({
            'token': token[:16] + '...',
            'url': data['url'],
            'created': data['created'],
            'expires': data['expires'],
            'active': data['active']
        })
    return jsonify({'links': links})

@app.route('/api/upload_image/<token>', methods=['POST'])
def upload_image(token):
    """Handle image upload"""
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No filename'}), 400
    
    # Save image
    import uuid
    ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
    filename = f"{uuid.uuid4()}.{ext}"
    filepath = os.path.join('static/uploads', filename)
    file.save(filepath)
    
    return jsonify({
        'success': True,
        'url': f'/static/uploads/{filename}'
    })

@app.route('/api/members/<token>', methods=['GET'])
def get_members(token):
    """Get list of active members"""
    members = []
    for sid, user in active_users.items():
        if user['token'] == token:
            members.append({
                'username': user['username'],
                'joined': user.get('join_time', '')
            })
    return jsonify({
        'count': len(members),
        'members': members
    })

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
        'room': token,
        'join_time': datetime.now().isoformat()
    }
    
    join_room(token)
    
    # Get member count
    member_count = sum(1 for u in active_users.values() if u['token'] == token)
    
    # Notify host
    socketio.emit('host_update', {
        'type': 'user_joined',
        'username': username,
        'timestamp': datetime.now().isoformat()
    }, room='host')
    
    emit('user_joined', {
        'username': username,
        'member_count': member_count,
        'timestamp': datetime.now().isoformat()
    }, room=token)
    
    print(f"{username} joined (total: {member_count})")

@socketio.on('message')
def handle_message(data):
    """Handle chat message"""
    user = active_users.get(request.sid)
    if not user:
        return
    
    message_data = {
        'username': user['username'],
        'message': data.get('message', ''),
        'image_url': data.get('image_url'),
        'reply_to': data.get('reply_to'),
        'timestamp': datetime.now().isoformat(),
        'message_id': secrets.token_urlsafe(8)
    }
    
    # Store for host
    chat_messages.append(message_data)
    if len(chat_messages) > 100:
        chat_messages.pop(0)
    
    # Broadcast
    emit('message', message_data, room=user['room'])
    
    # Notify host
    socketio.emit('host_update', {
        'type': 'message',
        'data': message_data
    }, room='host')
    
    print(f"{user['username']}: {message_data['message']}")

@socketio.on('join_host')
def handle_join_host():
    """Host joins monitoring"""
    join_room('host')
    print("Host joined")

@socketio.on('disconnect')
def handle_disconnect():
    """User disconnects"""
    user = active_users.pop(request.sid, None)
    if user:
        leave_room(user['room'])
        
        # Get member count
        member_count = sum(1 for u in active_users.values() if u['token'] == user['token'])
        
        # Notify host
        socketio.emit('host_update', {
            'type': 'user_left',
            'username': user['username'],
            'timestamp': datetime.now().isoformat()
        }, room='host')
        
        emit('user_left', {
            'username': user['username'],
            'member_count': member_count,
            'timestamp': datetime.now().isoformat()
        }, room=user['room'])
        
        print(f"{user['username']} left (remaining: {member_count})")

def open_browser():
    """Open browser"""
    import time
    time.sleep(1.5)
    webbrowser.open('http://localhost:5001')

if __name__ == '__main__':
    print("="*60)
    print("  🔐 SPIFFY PRIVATE CHAT - ENHANCED")
    print("  Reply • Images • Member List")
    print("="*60)
    print("\n🎛️  Dashboard: http://localhost:5001\n")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=False, allow_unsafe_werkzeug=True)
