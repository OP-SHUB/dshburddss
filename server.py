#!/usr/bin/env python3
"""
acw_sc__v2 token server (replaces the CN31 slider-token server).

The current checker uses pure-request acw_sc__v2 tokens produced by
mass_token_solver.py, each of which is BOUND to the sticky proxy exit that
solved it. A token is only valid when replayed through that SAME proxy, and
it lives ~600s (measured: 1006 requests / ~600s before re-challenge).

Token line format (matches tokens.txt):
    proxy|acw_tc|acw_sc__v2

The server keeps a per-proxy queue, enforces the real TTL, and serves tokens
only to clients asking for the exact sticky proxy that owns them.

Endpoints:
    POST /api/save-token   {proxy, token, acw_tc} or {line}
    GET  /api/get-token?proxy=...      (consumes one matching token)
    GET  /api/token/bulk?n=5&proxy=...
    GET  /api/status
    DELETE /api/tokens
    GET  /health
"""
import os
import re
import time
import threading
import argparse
from collections import deque
from datetime import datetime
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS

app = Flask(__name__, template_folder=".", static_folder=".")
CORS(app)

# Measured acw token ceiling: ~600s. Store with margin.
DEFAULT_TTL = 600
TOKEN_DIR = os.path.join(os.path.sep, "tmp", "acw_tokens")
LIVE_FILE = os.path.join(TOKEN_DIR, "live_tokens.txt")
SERVED_FILE = os.path.join(TOKEN_DIR, "served_tokens.txt")
EXPIRED_FILE = os.path.join(TOKEN_DIR, "expired_tokens.txt")
RECEIVED_COUNT_FILE = os.path.join(TOKEN_DIR, "received_count.txt")
SERVED_COUNT_FILE = os.path.join(TOKEN_DIR, "served_count.txt")

os.makedirs(TOKEN_DIR, exist_ok=True)

TOKEN_TTL = DEFAULT_TTL
_file_lock = threading.Lock()


def _append_file(path, line):
    with _file_lock:
        with open(path, "a") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())


def _write_count(path, count):
    with _file_lock:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(count))
        os.replace(tmp, path)


def _read_count(path):
    with _file_lock:
        try:
            with open(path, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0


def _file_lines(path):
    try:
        with open(path, "r") as f:
            return sum(1 for _ in f)
    except Exception:
        return 0


def _tail_lines(path, n=20):
    """Return the last n non-empty lines of a file (newest last)."""
    try:
        with open(path, "r") as f:
            lines = [ln.rstrip("\n") for ln in f if ln.strip()]
        return lines[-n:]
    except Exception:
        return []


# ── token normalization ──────────────────────────────────────────────────────
# A token belongs to a sticky proxy. Clients may pass the raw line
# (`host:port:user:pass` or a URL) or the sticky URL; we key on the provider
# root so lookup is stable.
_PROXY_URL_RE = re.compile(r"^(https?://)([^:@/]+?):([^@/]+)@([^:/]+):(\d+)$")


def _norm_proxy(p):
    p = (p or "").strip()
    if not p:
        return None
    m = _PROXY_URL_RE.match(p)
    if m:
        return p
    m = re.match(r"^([^:]+):(\d+):([^:]+):(.+)$", p)
    if m:
        host, port, user, pw = m.groups()
        return "http://%s:%s@%s:%s" % (user, pw, host, port)
    return p


def _base_key(p):
    """Strip the sticky `-sessid-<id>`/`-sess-<id>` tag for grouping."""
    p = _norm_proxy(p) or ""
    m = _PROXY_URL_RE.match(p)
    if not m:
        return p
    scheme, user, _pw, host, port = m.groups()
    user = re.sub(r"-(?:session|sess(?:id)?)-[^-]+$", "", user)
    return "%s%s@%s:%s" % (scheme, user, host, port)


_lock = threading.Lock()
# proxy_base -> deque of {proxy, tc, token, ts}
_token_queues = {}
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


def _write_expired(line):
    _append_file(EXPIRED_FILE, line)


def _write_served(line):
    _append_file(SERVED_FILE, line)


def _total_queue():
    return sum(len(q) for q in _token_queues.values())


def _purge_expired():
    """Pop expired entries across all per-proxy queues."""
    now = time.time()
    expired = []
    for base, q in list(_token_queues.items()):
        while q and (now - q[0]["ts"]) > TOKEN_TTL:
            e = q.popleft()
            _token_seen.discard(e["token"])
            expired.append("%s|%s|%s" % (e["proxy"], e["tc"] or "", e["token"]))
        if not q:
            _token_queues.pop(base, None)
    if expired:
        _stats["expired"] += len(expired)
    return expired


def _cleanup_loop():
    while True:
        time.sleep(0.2)
        with _lock:
            expired = _purge_expired()
        for line in expired:
            _write_expired(line)


_cleaner = threading.Thread(target=_cleanup_loop, daemon=True)
_cleaner.start()


def _parse_token_data(data):
    """Accept either {proxy, token, acw_tc} or {line: 'proxy|tc|token'}."""
    proxy = tc = token = None
    if data.get("line"):
        parts = str(data["line"]).split("|")
        if len(parts) == 3:
            proxy, tc, token = parts[0], parts[1], parts[2]
    else:
        proxy = data.get("proxy") or data.get("ip") or data.get("exit")
        token = data.get("token")
        tc = data.get("acw_tc") or data.get("tc")
    proxy = _norm_proxy(proxy) if proxy else None
    token = (token or "").strip()
    tc = (tc or "").strip()
    if not proxy or not token:
        return None, None, None
    return proxy, tc, token


@app.route("/api/save-token", methods=["POST"])
def receive_token():
    data = request.get_json(silent=True) or {}
    proxy, tc, token = _parse_token_data(data)
    if not proxy or len(token) < 20:
        return jsonify({"error": "missing 'proxy'/'token' (or valid line)"}), 400

    base = _base_key(proxy)
    added = False
    qsize = 0
    total_recv = 0
    with _lock:
        if token not in _token_seen:
            _token_seen.add(token)
            _token_queues.setdefault(base, deque()).append(
                {"proxy": proxy, "tc": tc, "token": token, "ts": time.time()})
            _stats["received"] += 1
            _stats["last_received"] = datetime.now().isoformat()
            added = True
            qsize = len(_token_queues[base])
            total_recv = _stats["received"]
            if _total_queue() > _stats["peak_queue"]:
                _stats["peak_queue"] = _total_queue()
        else:
            _stats["duplicates"] += 1

    if added:
        _append_file(LIVE_FILE, "%d|%s|%s|%s" % (
            int(time.time()), proxy, tc, token))
        _write_count(RECEIVED_COUNT_FILE, total_recv)

    return jsonify({
        "status": "ok",
        "added": added,
        "proxy": proxy,
        "queue_size": qsize,
        "total_received": total_recv,
    }), 200


def _pop_token(proxy):
    base = _base_key(proxy)
    q = _token_queues.get(base)
    if not q:
        return None, 0, 0
    entry = q.pop()
    _token_seen.discard(entry["token"])
    if not q:
        _token_queues.pop(base, None)
    return entry, len(_token_queues.get(base, [])), 0


@app.route("/api/get-token", methods=["GET"])
def get_token():
    proxy = _norm_proxy(request.args.get("proxy") or request.args.get("ip"))
    if not proxy:
        return jsonify({"error": "missing 'proxy' param", "remaining": 0}), 400

    token = None
    remaining = 0
    age = 0
    expired_lines = []
    served_count = 0
    with _lock:
        expired_lines = _purge_expired()
        entry, remaining, _ = _pop_token(proxy)
        if entry:
            token = entry["token"]
            age = round(time.time() - entry["ts"], 1)
            _stats["served"] += 1
            served_count = _stats["served"]
            _stats["last_served"] = datetime.now().isoformat()
    for line in expired_lines:
        _write_expired(line)
    if token:
        _write_served("%s|%s|%s" % (proxy, entry["tc"] or "", token))
        _write_count(SERVED_COUNT_FILE, served_count)
        return jsonify({
            "token": token,
            "acw_tc": entry["tc"] or "",
            "proxy": proxy,
            "remaining": remaining,
            "age_seconds": age,
        }), 200
    return jsonify({"error": "no tokens for this proxy", "remaining": 0}), 404


@app.route("/api/token/bulk", methods=["GET"])
def get_tokens_bulk():
    proxy = _norm_proxy(request.args.get("proxy") or request.args.get("ip"))
    n = request.args.get("n", 1, type=int)
    n = max(1, min(n, 100))
    if not proxy:
        return jsonify({"error": "missing 'proxy' param", "count": 0}), 400

    tokens = []
    served_count = 0
    expired_lines = []
    with _lock:
        expired_lines = _purge_expired()
        for _ in range(n):
            entry, remaining, _ = _pop_token(proxy)
            if not entry:
                break
            tokens.append({
                "token": entry["token"],
                "acw_tc": entry["tc"] or "",
                "proxy": entry["proxy"],
            })
            _stats["served"] += 1
        if tokens:
            served_count = _stats["served"]
            _stats["last_served"] = datetime.now().isoformat()
    for line in expired_lines:
        _write_expired(line)
    for t in tokens:
        _write_served("%s|%s|%s" % (t["proxy"], t["acw_tc"], t["token"]))
    if tokens:
        _write_count(SERVED_COUNT_FILE, served_count)

    return jsonify({
        "tokens": tokens,
        "count": len(tokens),
        "remaining": _total_queue(),
    }), 200


@app.route("/api/status", methods=["GET"])
def status():
    with _lock:
        expired_lines = _purge_expired()
        elapsed = time.time() - _stats["start_time"]
        total_received = max(_stats["received"], _read_count(RECEIVED_COUNT_FILE))
        total_served = max(_stats["served"], _read_count(SERVED_COUNT_FILE))
        total_expired = max(_stats["expired"], _file_lines(EXPIRED_FILE))
        rate = total_received / (elapsed / 60) if elapsed > 0 else 0

        per_proxy = []
        for base, q in sorted(_token_queues.items(), key=lambda kv: -len(kv[1])):
            per_proxy.append({
                "proxy": base,
                "count": len(q),
                "oldest_age": round(time.time() - q[0]["ts"], 1) if q else 0,
            })

        recent_tokens = []
        # Persistent solved tokens (written on save): these always show up even
        # after a token has been served or the server restarted. Line format:
        #   <epoch>|<proxy>|<tc>|<token>
        now = time.time()
        for line in _tail_lines(LIVE_FILE, 20):
            parts = line.split("|")
            if len(parts) == 4:
                try:
                    ts = int(parts[0])
                except ValueError:
                    ts = now
                recent_tokens.append({
                    "proxy": _base_key(parts[1]),
                    "token": (parts[3] or "")[:16] + "…",
                    "age": round(max(0.0, now - ts), 1),
                })
        # Augment with whatever is still live in the queue (freshest first).
        for base, q in _token_queues.items():
            for item in list(q)[-3:]:
                recent_tokens.append({
                    "proxy": base,
                    "token": item["token"][:16] + "…",
                    "age": round(time.time() - item["ts"], 1),
                })
        # de-dup by token prefix, keep newest, newest-last
        seen = set()
        dedup = []
        for t in reversed(recent_tokens):
            if t["token"] in seen:
                continue
            seen.add(t["token"])
            dedup.append(t)
        recent_tokens = dedup[-12:][::-1]

        result = jsonify({
            "queue_size": _total_queue(),
            "per_proxy": per_proxy,
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
    for line in expired_lines:
        _write_expired(line)
    return result


@app.route("/api/tokens", methods=["DELETE"])
def flush_tokens():
    removed = 0
    with _lock:
        for base, q in list(_token_queues.items()):
            removed += len(q)
            _token_queues.pop(base, None)
        _stats["flushed"] += removed
    return jsonify({"status": "flushed", "removed": removed}), 200


@app.route("/api/tokens/count", methods=["GET"])
def token_count():
    with _lock:
        return jsonify({
            "queue_size": _total_queue(),
            "total_received": max(_stats["received"], _read_count(RECEIVED_COUNT_FILE)),
            "total_served": max(_stats["served"], _read_count(SERVED_COUNT_FILE)),
        }), 200


@app.route("/", methods=["GET"])
def dashboard():
    return render_template("dashboard.html")


@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(".", filename)


@app.route("/health", methods=["GET"])
def health():
    with _lock:
        return jsonify({
            "ok": True,
            "uptime": round(time.time() - _stats["start_time"], 1),
            "queue_size": _total_queue(),
            "total_received": max(_stats["received"], _read_count(RECEIVED_COUNT_FILE)),
        })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--ttl", type=int, default=DEFAULT_TTL)
    args = parser.parse_args()

    TOKEN_TTL = args.ttl

    print(f"""
[ acw_sc__v2 Token Server v3.0 ]
  Token Dir : {TOKEN_DIR}
  Live      : {LIVE_FILE}
  Expired   : {EXPIRED_FILE}
  Port      : {args.port}
  TTL       : {args.ttl}s (proxy-bound, measured ceiling ~600s)
  URL       : http://{args.host}:{args.port}
""")

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
