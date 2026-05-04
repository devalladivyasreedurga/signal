import sys
import os
import json
import hashlib
import threading
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS

from server.database import (
    init_db, register_user, get_user, get_prekey_bundle,
    save_session, get_session, list_users, save_message, get_history,
)
from server.queue import enqueue_message, dequeue_messages, get_pubsub, ping

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# net_id -> socket session id
_online: dict[str, str] = {}


# ─── REST endpoints ───────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"redis": ping(), "status": "ok"})


@app.route("/register", methods=["POST"])
def register():
    data = request.json
    net_id      = data.get("net_id", "").strip().lower()
    password    = data.get("password", "")
    ik_pub      = data.get("ik_pub")
    spk_pub     = data.get("spk_pub")
    opk_pubs    = data.get("opk_pubs", [])
    ik_sign_pub = data.get("ik_sign_pub")   # base64 raw ECDSA P-256 public key
    spk_sig     = data.get("spk_sig")       # base64 ECDSA signature over spk_pub hex

    if not all([net_id, password, ik_pub, spk_pub, opk_pubs]):
        return jsonify({"error": "Missing fields"}), 400

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    ok = register_user(net_id, pw_hash, str(ik_pub), str(spk_pub), [str(o) for o in opk_pubs],
                       ik_sign_pub=ik_sign_pub, spk_sig=spk_sig)
    if not ok:
        return jsonify({"error": "net_id already registered"}), 409
    return jsonify({"ok": True})


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    net_id = data.get("net_id", "").strip().lower()
    password = data.get("password", "")
    user = get_user(net_id)
    if not user:
        return jsonify({"error": "Unknown user"}), 404
    if user["password"] != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({"error": "Wrong password"}), 401
    return jsonify({"ok": True, "net_id": net_id, "fingerprint": user["fingerprint"]})


@app.route("/bundle/<net_id>")
def bundle(net_id):
    b = get_prekey_bundle(net_id)
    if not b:
        return jsonify({"error": "User not found"}), 404
    return jsonify(b)


@app.route("/users")
def users():
    me = request.args.get("me", "")
    return jsonify(list_users(me))


@app.route("/online")
def online():
    return jsonify(list(_online.keys()))


@app.route("/send", methods=["POST"])
def send_message():
    data = request.json
    recipient = data.get("recipient")
    sender = data.get("sender")
    payload = data.get("payload")

    if not all([recipient, sender, payload]):
        return jsonify({"error": "Missing fields"}), 400

    msg = {"id": str(uuid.uuid4()), "sender": sender, "payload": payload}
    save_message(sender, recipient, json.dumps(payload))

    sid = _online.get(recipient)
    if sid:
        socketio.emit("message", msg, room=sid)
    else:
        enqueue_message(recipient, msg)

    return jsonify({"ok": True})


@app.route("/history/<user_a>/<user_b>")
def history(user_a, user_b):
    rows = get_history(user_a, user_b)
    return jsonify(rows)


@app.route("/messages/<net_id>")
def fetch_messages(net_id):
    msgs = dequeue_messages(net_id)
    return jsonify(msgs)


# ─── WebSocket events ─────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    pass


@socketio.on("authenticate")
def on_auth(data):
    net_id = data.get("net_id", "").strip().lower()
    user = get_user(net_id)
    if not user:
        emit("error", {"msg": "Unknown user"})
        return
    _online[net_id] = request.sid
    join_room(request.sid)
    # Flush offline queue
    pending = dequeue_messages(net_id)
    for msg in pending:
        emit("message", msg)
    emit("authenticated", {"net_id": net_id, "fingerprint": user["fingerprint"]})
    # Broadcast updated online list to all connected clients
    socketio.emit("online_update", list(_online.keys()))


@socketio.on("disconnect")
def on_disconnect():
    dead = [k for k, v in _online.items() if v == request.sid]
    for k in dead:
        _online.pop(k, None)
    # Broadcast updated online list to all connected clients
    socketio.emit("online_update", list(_online.keys()))


@socketio.on("send_message")
def on_send(data):
    recipient = data.get("recipient")
    sender = data.get("sender")
    payload = data.get("payload")
    ts = data.get("ts")

    if not all([recipient, sender, payload]):
        return

    msg = {"id": str(uuid.uuid4()), "sender": sender, "payload": payload, "ts": ts}
    save_message(sender, recipient, json.dumps(payload))
    sid = _online.get(recipient)
    if sid:
        emit("message", msg, room=sid)
    else:
        enqueue_message(recipient, msg)


if __name__ == "__main__":
    init_db()
    socketio.run(app, host="0.0.0.0", port=5001, debug=False, allow_unsafe_werkzeug=True)
