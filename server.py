#!/usr/bin/env python3

import os
import time
import threading
import argparse
from collections import deque
from datetime import datetime
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

app = Flask(__name__, 
            template_folder='.',
            static_folder='.')
CORS(app)

TOKEN_TTL = 900
TOKEN_DIR = os.path.join(os.path.sep, 'tmp', 'cn31_tokens')
LIVE_FILE = os.path.join(TOKEN_DIR, 'live_tokens.txt')
SERVED_FILE = os.path.join(TOKEN_DIR, 'served_tokens.txt')
EXPIRED_FILE = os.path.join(TOKEN_DIR, 'expired_tokens.txt')
RECEIVED_COUNT_FILE = os.path.join(TOKEN_DIR, 'received_count.txt')
SERVED_COUNT_FILE = os.path.join(TOKEN_DIR, 'served_count.txt')

os.makedirs(TOKEN_DIR, exist_ok=True)

_file_lock = threading.Lock()

def _append_file(path, token):
    with _file_lock:
        with open(path, 'a') as f:
            f.write(token + '\n')

def _write_count(path, count):
    with _file_lock:
        with open(path, 'w') as f:
            f.write(str(count))

def _read_count(path):
    with _file_lock:
        try:
            with open(path, 'r') as f:
                return int(f.read().strip())
        except:
            return 0

_lock = threading.Lock()
_token_queue = deque()
_token_seen = set()
_stats = {
    "received": 0,
    "served": 0,
    "expired": 0,
    "duplicates": 0,
    "flushed": 0,
    "start_time": time.time(),
    "peak_queue": 0,
    "last_received": None,
    "last_served": None,
}

def _file_lines(path):
    try:
        with open(path, 'r') as f:
            return sum(1 for _ in f)
    except:
        return 0

def _write_expired(token):
    _append_file(EXPIRED_FILE, token)

def _write_served(token):
    _append_file(SERVED_FILE, token)

def _pop_one_expired():
    now = time.time()
    if _token_queue and (now - _token_queue[0]["ts"]) > TOKEN_TTL:
        t = _token_queue.popleft()["token"]
        _token_seen.discard(t)
        _stats["expired"] += 1
        return t
    return None

def _purge_expired():
    now = time.time()
    expired = []
    while _token_queue and (now - _token_queue[0]["ts"]) > TOKEN_TTL:
        t = _token_queue.popleft()["token"]
        _token_seen.discard(t)
        expired.append(t)
    if expired:
        _stats["expired"] += len(expired)
    return expired

def _cleanup_loop():
    while True:
        time.sleep(0.15)
        with _lock:
            t = _pop_one_expired()
        if t:
            _write_expired(t)

_cleaner = threading.Thread(target=_cleanup_loop, daemon=True)
_cleaner.start()

@app.route("/api/save-token", methods=["POST"])
def receive_token():
    data = request.get_json(silent=True)
    if not data or "token" not in data:
        return jsonify({"error": "missing 'token' field"}), 400

    token = str(data["token"]).strip()
    if not token or len(token) < 20:
        return jsonify({"error": "invalid token"}), 400

    added = False
    with _lock:
        if token not in _token_seen:
            _token_seen.add(token)
            _token_queue.append({"token": token, "ts": time.time()})
            _stats["received"] += 1
            _stats["last_received"] = datetime.now().isoformat()
            added = True
            qs = len(_token_queue)
            if qs > _stats["peak_queue"]:
                _stats["peak_queue"] = qs
        else:
            _stats["duplicates"] += 1

    if added:
        _append_file(LIVE_FILE, token)
        _write_count(RECEIVED_COUNT_FILE, _stats["received"])

    return jsonify({
        "status": "ok",
        "added": added,
        "queue_size": len(_token_queue),
        "total_received": _stats["received"],
    }), 200

@app.route("/api/get-token", methods=["GET"])
def get_token():
    token = None
    remaining = 0
    age = 0
    expired_token = None
    with _lock:
        expired_token = _pop_one_expired()
        if _token_queue:
            entry = _token_queue.pop()
            token = entry["token"]
            _token_seen.discard(token)
            remaining = len(_token_queue)
            age = round(time.time() - entry["ts"], 1)
            _stats["served"] += 1
            _stats["last_served"] = datetime.now().isoformat()
    if expired_token:
        _write_expired(expired_token)
    if token:
        _write_served(token)
        _write_count(SERVED_COUNT_FILE, _stats["served"])
        return jsonify({"token": token, "remaining": remaining, "age_seconds": age}), 200
    return jsonify({"error": "no tokens available", "remaining": 0}), 404

@app.route("/api/token/bulk", methods=["GET"])
def get_tokens_bulk():
    n = request.args.get("n", 1, type=int)
    n = max(1, min(n, 100))

    tokens = []
    with _lock:
        for _ in range(n):
            if _token_queue:
                entry = _token_queue.pop()
                _token_seen.discard(entry["token"])
                tokens.append(entry["token"])
                _stats["served"] += 1
            else:
                break
        if tokens:
            _stats["last_served"] = datetime.now().isoformat()
    for t in tokens:
        _write_served(t)
    if tokens:
        _write_count(SERVED_COUNT_FILE, _stats["served"])

    return jsonify({
        "tokens": tokens,
        "count": len(tokens),
        "remaining": len(_token_queue),
    }), 200

@app.route("/api/status", methods=["GET"])
def status():
    with _lock:
        elapsed = time.time() - _stats["start_time"]
        total_received = max(_stats["received"], _read_count(RECEIVED_COUNT_FILE))
        total_served = max(_stats["served"], _read_count(SERVED_COUNT_FILE))
        total_expired = max(_stats["expired"], _file_lines(EXPIRED_FILE))
        rate = total_received / (elapsed / 60) if elapsed > 0 else 0
        recent_tokens = []
        for item in list(_token_queue)[-5:]:
            recent_tokens.append({
                "token": item["token"][:40] + "...",
                "age": round(time.time() - item["ts"], 1)
            })
        result = jsonify({
            "queue_size": len(_token_queue),
            "total_received": total_received,
            "total_served": total_served,
            "total_expired": total_expired,
            "total_duplicates": _stats["duplicates"],
            "total_flushed": _stats["flushed"],
            "peak_queue": _stats["peak_queue"],
            "uptime_seconds": round(elapsed, 1),
            "tokens_per_minute": round(rate, 2),
            "token_ttl_seconds": TOKEN_TTL,
            "last_received": _stats["last_received"],
            "last_served": _stats["last_served"],
            "recent_tokens": recent_tokens,
        }), 200
    return result

@app.route("/api/tokens", methods=["DELETE"])
def flush_tokens():
    with _lock:
        tokens = list(_token_queue)
        _token_queue.clear()
        _stats["flushed"] += len(tokens)
    for item in tokens:
        _write_expired(item["token"])
    return jsonify({"status": "flushed", "removed": len(tokens)}), 200

@app.route("/api/tokens/count", methods=["GET"])
def token_count():
    with _lock:
        result = jsonify({
            "queue_size": len(_token_queue),
            "total_received": max(_stats["received"], _read_count(RECEIVED_COUNT_FILE)),
            "total_served": max(_stats["served"], _read_count(SERVED_COUNT_FILE)),
        }), 200
    return result

@app.route("/", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory('.', filename)

@app.route("/health", methods=["GET"])
def health():
    with _lock:
        result = jsonify({
            "ok": True,
            "uptime": round(time.time() - _stats["start_time"], 1),
            "queue_size": len(_token_queue),
            "total_received": max(_stats["received"], _read_count(RECEIVED_COUNT_FILE)),
        })
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--ttl", type=int, default=900)
    args = parser.parse_args()

    TOKEN_TTL = args.ttl

    print(f"""
[ CN31 Token Server v2.0 ]
  Token Dir : {TOKEN_DIR}
  Live      : {LIVE_FILE}
  Expired   : {EXPIRED_FILE}
  Port      : {args.port}
  TTL       : {args.ttl}s
  URL       : http://{args.host}:{args.port}
""")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
