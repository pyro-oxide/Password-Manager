import os
from pathlib import Path

# Application settings
APP_NAME = "Secure Password Manager"
APP_VERSION = "1.0.0"
DB_NAME = "secure_vault.db" # Changed name slightly
DB_BACKUP_PATH = "secure_vault_backup.json.enc"
KEY_FILE = "key.key" # This should NOT be used if key is derived from master password
LOG_FILE = "password_manager.log"
AUTO_LOCK_TIMEOUT_MINUTES = 15 # Minutes of inactivity before lock

# Email settings (Placeholder - Use securely stored config or env variables in real app)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "samarth.532.2026@doonschool.com"  # Add your email here - Use environment variables or secure config
SENDER_PASSWORD = "twnj gfce effr dcxj"  # Add your app password here - Use environment variables or secure config

# Security settings
SALT_LENGTH = 16 # 16 bytes is common for salt
KEY_LENGTH = 32 # For PBKDF2 derived key hash
ITERATIONS = 390000 # OWASP recommended minimum for PBKDF2-HMAC-SHA256 (as of 2023)
CLIPBOARD_CLEAR_TIMEOUT_SECONDS = 30 # Seconds before clearing copied password

# Paths
BASE_DIR = Path(__file__).parent.resolve() # Use resolve() for absolute path
DATA_DIR = BASE_DIR / "data" # Store data files in a sub-directory
DB_PATH = DATA_DIR / DB_NAME
# KEY_PATH = DATA_DIR / KEY_FILE # Don't store derived key
LOG_PATH = DATA_DIR / LOG_FILE
ICON_PATH = BASE_DIR / "icons" # Optional: for custom icons

# Create necessary directories
DATA_DIR.mkdir(exist_ok=True)
ICON_PATH.mkdir(exist_ok=True)

# 2FA Settings
TOTP_ISSUER_NAME = APP_NAME