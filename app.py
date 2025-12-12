import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from config import (
    FLASK_SECRET_KEY,
    OWNER_ID, APP_SECRET, API_KEY,
    APP_NAME,
    PANEL_USERNAME, PANEL_PASSWORD
)
import storage

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY


# ---------- client IP helper ----------
def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr)


# ---------- (optional) login helper ----------
def login_required():
    # ab actual login system use nahi kar rahe
    return True


# ---------- Auth routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    # koi login.html nahi, direct home pe bhej do
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("home"))


# ---------- HTML route ----------
@app.route("/", methods=["GET"])
def home():
    # seedha index.html render
    return render_template("index.html")


# ---------- small auth helper (owner/secret/apiKey headers) ----------
def check_headers():
    h_owner = request.headers.get("X-Owner-Id")
    h_secret = request.headers.get("X-Secret")
    h_api = request.headers.get("X-Api-Key")
    return h_owner == OWNER_ID and h_secret == APP_SECRET and h_api == API_KEY


# ---------- API routes ----------
@app.route("/info", methods=["GET"])
def info():
    return jsonify({
        "app_name": APP_NAME,
        "owner_id": OWNER_ID
    })


@app.route("/generate", methods=["POST"])
def generate():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    username = data.get("username", "User")
    plan = data.get("plan")
    days = data.get("days")
    hwid_lock = bool(data.get("hwid_lock", False))
    max_uses = data.get("max_uses")

    key, meta = storage.create_key(
        username=username,
        plan=plan,
        days=days,
        hwid_lock=hwid_lock,
        max_uses=max_uses
    )
    storage.add_log("generate", key, {"username": username, "plan": meta["plan"]})

    return jsonify({
        "success": True,
        "message": "Key created",
        "key": key,
        "data": meta
    })


@app.route("/verify", methods=["POST"])
def verify():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")

    if not key or not hwid:
        return jsonify({
            "success": False,
            "status": "bad_request",
            "message": "key & hwid required"
        }), 400

    client_ip = get_client_ip()
    ok, status, msg, meta = storage.verify_key_logic(key, hwid, client_ip)
    storage.add_log("verify", key, {"status": status, "ip": client_ip})

    return jsonify({
        "success": ok,
        "status": status,
        "message": msg,
        "data": meta
    })


@app.route("/keys", methods=["GET"])
def list_keys():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    db = storage.load_db()
    return jsonify({
        "success": True,
        "keys": db
    })


@app.route("/ban", methods=["POST"])
def ban():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    banned = bool(data.get("banned", True))

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.set_banned(key, banned, reason="Panel toggle")
    storage.add_log("ban", key, {"banned": banned})

    return jsonify({"success": ok})


@app.route("/reset_hwid", methods=["POST"])
def reset_hwid():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.reset_hwid(key)
    storage.add_log("reset_hwid", key, {})

    return jsonify({"success": ok})


@app.route("/delete", methods=["POST"])
def delete():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.delete_key(key)
    storage.add_log("delete", key, {})

    return jsonify({"success": ok})


@app.route("/logs", methods=["GET"])
def logs():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    return jsonify({
        "success": True,
        "logs": storage.load_logs()
    })


if __name__ == "__main__":
    print("🚀 KeyAuth backend running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
