# backend/storage.py
import json, os, hashlib, uuid
from datetime import datetime, timedelta
from config import (
    DB_FILE, LOG_FILE,
    DEFAULT_PLAN, DEFAULT_DAYS, DEFAULT_MAX_USES,
    HWID_FIELD, IP_FIELD, EXPIRES_FIELD
)

def _now():
    return datetime.utcnow()

# ---------- DB helpers ----------
def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []

def save_logs(logs):
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

# ---------- HWID helper ----------
def get_hwid():
    return hashlib.md5(str(uuid.getnode()).encode()).hexdigest()[:16]

# ---------- Key create / manage ----------
def create_key(username="User", plan=None, days=None,
               hwid_lock=False, max_uses=None):
    import secrets, base64
    data = load_db()

    raw = secrets.token_bytes(16)
    key = base64.b64encode(raw).decode()

    plan = plan or DEFAULT_PLAN
    days = days if days is not None else DEFAULT_DAYS

    # 👈 DC BOT: NO 10 LIMIT, exact days
    if max_uses is None:
        max_uses = DEFAULT_MAX_USES  # Config se le

    created = _now()
    expiry = created + timedelta(days=days)

    data[key] = {
        "username": username,
        "plan": plan,
        "created": created.isoformat(),
        "expiry": expiry.isoformat(),  # 👈 EXPIRES_FIELD match
        "hwid_lock": hwid_lock,
        HWID_FIELD: None,              # 👈 Config field use
        "valid": True,
        "banned": False,
        "uses": 0,
        "max_uses": max_uses,
        "last_used": None,
        IP_FIELD: None,                # 👈 Config field use (last_ip)
        "ban_reason": None
    }

    save_db(data)
    return key, data[key]

def set_banned(key, banned: bool, reason: str = None):
    data = load_db()
    if key in data:
        data[key]["banned"] = banned
        data[key]["ban_reason"] = reason
        save_db(data)
        return True
    return False

def reset_hwid(key):
    data = load_db()
    if key in data:
        data[key][HWID_FIELD] = None
        data[key]["hwid_lock"] = False
        save_db(data)
        return True
    return False

def delete_key(key):
    data = load_db()
    if key in data:
        del data[key]
        save_db(data)
        return True
    return False

# ---------- Verify core logic ----------
def verify_key_logic(key, client_hwid: str, client_ip: str = None):
    data = load_db()
    if key not in data:
        return False, "invalid", "Key not found", None

    k = data[key]

    # banned / disabled
    if not k.get("valid", True) or k.get("banned", False):
        return False, "banned", "Key banned/disabled", k

    # expiry check
    expiry = datetime.fromisoformat(k[EXPIRES_FIELD])  # 👈 Config field
    if _now() > expiry:
        k["valid"] = False
        save_db(data)
        return False, "expired", "Key expired", k

    # max uses
    if k.get("max_uses") is not None and k["uses"] >= k["max_uses"]:
        k["valid"] = False
        save_db(data)
        return False, "max_uses", "Maximum uses reached", k

    # HWID logic
    if k.get("hwid_lock", False):
        if k.get(HWID_FIELD) is None:
            # first bind
            k[HWID_FIELD] = client_hwid
        else:
            if k[HWID_FIELD] != client_hwid:
                save_db(data)
                return False, "hwid_mismatch", "HWID does not match", k

    # success → update uses + last_used + IP + HWID
    k["uses"] += 1
    k["last_used"] = _now().isoformat()
    if client_ip is not None:
        k[IP_FIELD] = client_ip  # 👈 Config field
    if client_hwid is not None:
        k[HWID_FIELD] = client_hwid  # 👈 Always update HWID

    save_db(data)
    return True, "success", "Key valid", k

# ---------- Logs helper ----------
def add_log(event_type, key=None, info=None):
    logs = load_logs()
    logs.append({
        "time": _now().isoformat(),
        "event": event_type,
        "key": key,
        "hwid": info.get("hwid") if info else None,  # 👈 HWID log
        "ip": info.get("ip") if info else None,      # 👈 IP log
        "info": info or {}
    })
    # Keep only last 1000 logs
    if len(logs) > 1000:
        logs = logs[-1000:]
    save_logs(logs)
