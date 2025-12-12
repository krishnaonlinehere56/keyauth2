# backend/storage.py
import json, os, hashlib, uuid
from datetime import datetime, timedelta
from config import (
    DB_FILE, LOG_FILE,
    DEFAULT_PLAN, DEFAULT_DAYS, DEFAULT_MAX_USES
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
    # server side ke liye; client apna hwid bhejega
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

    # yahi se default 10 uses enforce kar rahe hain
    if max_uses is None:
        max_uses = 10
    # agar kabhi config se lena ho to: max_uses = max_uses or DEFAULT_MAX_USES

    created = _now()
    expiry = created + timedelta(days=days)

    data[key] = {
        "username": username,
        "plan": plan,
        "created": created.isoformat(),
        "expiry": expiry.isoformat(),
        "hwid_lock": hwid_lock,
        "hwid": None,
        "valid": True,
        "banned": False,
        "uses": 0,
        "max_uses": max_uses,
        "last_used": None,
        "last_ip": None,
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
        data[key]["hwid"] = None
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

    # expiry
    expiry = datetime.fromisoformat(k["expiry"])
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
        if k.get("hwid") is None:
            # first bind
            k["hwid"] = client_hwid
        else:
            if k["hwid"] != client_hwid:
                save_db(data)
                return False, "hwid_mismatch", "HWID does not match", k

    # success → update uses + last_used + last_ip
    k["uses"] += 1
    k["last_used"] = _now().isoformat()
    if client_ip is not None:
        k["last_ip"] = client_ip

    save_db(data)
    return True, "success", "Key valid", k


# ---------- Logs helper ----------

def add_log(event_type, key=None, info=None):
    logs = load_logs()
    logs.append({
        "time": _now().isoformat(),
        "event": event_type,
        "key": key,
        "info": info or {}
    })
    save_logs(logs)
