# server.py
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-in-prod'
socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('connect')
def on_connect():
    print('Client connected', request.sid)

@socketio.on('register')
def on_register(data):
    username = data.get('username')
    if not username:
        return
    join_room(username)
    print(f"{username} registered (sid={request.sid})")
    emit('registered', {'status': 'ok'})

@socketio.on('handshake')
def on_handshake(data):
    to = data.get('to')
    if to:
        socketio.emit('handshake', data, room=to)
        print(f"Relayed handshake from {data.get('from')} to {to}")

@socketio.on('message')
def on_message(data):
    to = data.get('to')
    if to:
        socketio.emit('message', data, room=to)
        print(f"Relayed message from {data.get('from')} to {to}")

@socketio.on('disconnect')
def on_disconnect():
    print('Client disconnected', request.sid)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
