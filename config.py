import secrets
import os

# App identity (KeyAuth style)
APP_NAME   = "MyKeyAuth"
OWNER_ID   = "jkl4drh6"
APP_SECRET = "ioyskcnwtdnzoexis6283niisns"      # signing / extra checks ke liye
API_KEY    = "panel_789"       # panel + API auth

# Storage paths
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_FILE    = os.path.join(BASE_DIR, "keys.json")
LOG_FILE   = os.path.join(BASE_DIR, "logs.json")

# Security / defaults
FLASK_SECRET_KEY = secrets.token_hex(32)
DEFAULT_PLAN     = "BASIC"
DEFAULT_DAYS     = 30
DEFAULT_MAX_USES = 1

#WEBSITE PROTECTION 
PANEL_USERNAME = "778899"
PANEL_PASSWORD = "998877"
 