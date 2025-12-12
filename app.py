import os
from datetime import datetime, timedelta
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
    return True


# ---------- Auth routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect(url_for("home"))


@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("home"))


# ---------- HTML route ----------
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# ---------- small auth helper ----------
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
    plan = data.get("plan", "basic")
    days = data.get("days")
    
    if days is None:
        days = 7
    days = int(days)
    
    hwid_lock = bool(data.get("hwid_lock", False))
    max_uses = data.get("max_uses", 1)

    key, meta = storage.create_key(
        username=username,
        plan=plan,
        days=days,
        hwid_lock=hwid_lock,
        max_uses=max_uses
    )
    
    expiry_date = datetime.now() + timedelta(days=days)
    
    storage.add_log("generate", key, {
        "username": username, 
        "plan": plan,
        "days": days,
        "expires": expiry_date.isoformat()
    })

    return jsonify({
        "success": True,
        "message": f"Key created for {days} days",
        "key": key,
        "data": {
            **meta,
            "days": days,
            "expires": expiry_date.strftime("%Y-%m-%d"),
            "days_left": days
        }
    })


@app.route("/verify", methods=["POST"])
def verify():
    # 👈 NO AUTH - Client direct call karega
    data = request.get_json(silent=True) or {}
    key = data.get("key")
    hwid = data.get("hwid")

    if not key or not hwid:
        return jsonify({
            "success": False,
            "status": "bad_request",
            "message": "key & hwid required"
        }), 400

    # 👈 CLIENT PC KA HWID + IP CAPTURE
    client_ip = get_client_ip()
    client_hwid = hwid
    
    ok, status, msg, meta = storage.verify_key_logic(key, client_hwid, client_ip)
    
    # 👈 HWID + IP LOG SAVE
    storage.add_log("verify", key, {
        "status": status, 
        "ip": client_ip,
        "hwid": client_hwid
    })

    # 👈 RESPONSE ME HWID + IP BHI BHEJO
    return jsonify({
        "success": ok,
        "status": status,
        "message": msg,
        "data": {
            **meta,
            "client_ip": client_ip,
            "client_hwid": client_hwid
        }
    })


@app.route("/keys", methods=["GET"])
def list_keys():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    db = storage.load_db()
    keys_with_expiry = []
    
    for key_data in db:
        if 'expires' in key_data and key_data['expires']:
            expiry = datetime.fromisoformat(key_data['expires'])
            days_left = max(0, (expiry - datetime.now()).days)
        else:
            days_left = 0
            
        keys_with_expiry.append({
            **key_data,
            "days_left": days_left,
            "last_ip": key_data.get("last_ip", "N/A"),      # 👈 SHOW LAST IP
            "last_hwid": key_data.get("hwid", "N/A")        # 👈 SHOW LAST HWID
        })
    
    return jsonify({
        "success": True,
        "keys": keys_with_expiry,
        "total": len(keys_with_expiry)
    })


@app.route("/ban", methods=["POST"])
def ban():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")
    banned = data.get("banned", True)

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.set_banned(key, bool(banned), reason="DC Panel")
    storage.add_log("ban", key, {"banned": bool(banned)})
    
    return jsonify({
        "success": ok,
        "message": "Key banned/unbanned" if ok else "Key not found"
    })


@app.route("/reset_hwid", methods=["POST"])
def reset_hwid():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.reset_hwid(key)
    storage.add_log("reset_hwid", key, {"success": ok})
    
    return jsonify({
        "success": ok,
        "message": "HWID reset" if ok else "Key not found"
    })


@app.route("/delete", methods=["POST"])
def delete():
    if not check_headers():
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key = data.get("key")

    if not key:
        return jsonify({"success": False, "message": "key required"}), 400

    ok = storage.delete_key(key)
    storage.add_log("delete", key, {"success": ok})

    return jsonify({
        "success": ok,
        "message": "Key deleted" if ok else "Key not found"
    })


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
