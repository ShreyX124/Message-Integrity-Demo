from flask import Flask, request, render_template, jsonify
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64
import uuid

app = Flask(__name__)

# In-memory store for users and messages (for demo purposes)
users = {}  # {username: {"private_key": str, "public_key": str}}
messages = {}  # {message_id: {"sender": str, "recipient": str, "message": str, "signature": str, "tampered": bool}}

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def sign_message(private_key, message):
    try:
        key = RSA.import_key(private_key)
        hashed_msg = SHA256.new(message.encode())
        signature = pss.new(key).sign(hashed_msg)
        return base64.b64encode(signature).decode()
    except ValueError as e:
        raise ValueError(f"Invalid private key: {str(e)}")

def verify_signature(public_key, message, signature):
    try:
        key = RSA.import_key(public_key)
        hashed_msg = SHA256.new(message.encode())
        pss.new(key).verify(hashed_msg, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        if not username or not isinstance(username, str):
            return jsonify({"error": "Username must be a non-empty string"}), 400
        if username in users:
            return jsonify({"error": "Username already exists"}), 400
        private_key, public_key = generate_keys()
        users[username] = {"private_key": private_key, "public_key": public_key}
        return jsonify({"username": username, "public_key": public_key})
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    try:
        data = request.json
        sender = data.get('sender')
        recipient = data.get('recipient')
        message = data.get('message')
        if not all([sender, recipient, message]) or not isinstance(message, str):
            return jsonify({"error": "Sender, recipient, and message are required"}), 400
        if sender not in users or recipient not in users:
            return jsonify({"error": "Invalid sender or recipient"}), 400
        signature = sign_message(users[sender]["private_key"], message)
        message_id = str(uuid.uuid4())
        messages[message_id] = {
            "sender": sender,
            "recipient": recipient,
            "message": message,
            "signature": signature,
            "tampered": False
        }
        return jsonify({"message_id": message_id, "signature": signature})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/tamper_message', methods=['POST'])
def tamper_message():
    try:
        data = request.json
        message_id = data.get('message_id')
        new_message = data.get('new_message')
        if not message_id or not new_message or not isinstance(new_message, str):
            return jsonify({"error": "Message ID and new message are required"}), 400
        if message_id not in messages:
            return jsonify({"error": "Invalid message ID"}), 400
        messages[message_id]["message"] = new_message
        messages[message_id]["tampered"] = True
        return jsonify({"message_id": message_id, "status": "Message tampered"})
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@app.route('/verify_message', methods=['POST'])
def verify_message():
    try:
        data = request.json
        message_id = data.get('message_id')
        if not message_id:
            return jsonify({"error": "Message ID is required"}), 400
        if message_id not in messages:
            return jsonify({"error": "Invalid message ID"}), 400
        msg_data = messages[message_id]
        is_valid = verify_signature(
            users[msg_data["sender"]]["public_key"],
            msg_data["message"],
            msg_data["signature"]
        )
        return jsonify({
            "message_id": message_id,
            "sender": msg_data["sender"],
            "recipient": msg_data["recipient"],
            "message": msg_data["message"],
            "valid": is_valid,
            "tampered": msg_data["tampered"]
        })
    except Exception as e:
        return jsonify({"error": f"Server error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)