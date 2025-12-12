import secrets
import os

# App identity (KeyAuth style)
APP_NAME   = "MyKeyAuth"
OWNER_ID   = "jkl4drh6"                    # DC Bot ID same rakh
APP_SECRET = "ioyskcnwtdnzoexis6283niisns"  # DC Bot secret same
API_KEY    = "panel_789"                   # DC Bot + Panel same

# Storage paths
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_FILE    = os.path.join(BASE_DIR, "keys.json")
LOG_FILE   = os.path.join(BASE_DIR, "logs.json")

# Security / defaults
FLASK_SECRET_KEY = secrets.token_hex(32)
DEFAULT_PLAN     = "BASIC"
DEFAULT_DAYS     = 7                       # 👈 DC ke liye 7 default
DEFAULT_MAX_USES = 1
MAX_DAYS_LIMIT   = 365                     # 👈 1 year max (DC free)

# WEBSITE PROTECTION 
PANEL_USERNAME = "778899"
PANEL_PASSWORD = "998877"

# 👈 HWID + IP TRACKING FIELDS (storage.py use karega)
HWID_FIELD     = "hwid"
IP_FIELD       = "last_ip"
EXPIRES_FIELD  = "expires"
