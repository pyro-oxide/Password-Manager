import logging
import hashlib
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from config import LOG_PATH, SALT_LENGTH, KEY_LENGTH, ITERATIONS, DATA_DIR
import zxcvbn
import json
from typing import Dict, Any, Optional, Tuple, List
import time
import pyotp # Required for 2FA
import qrcode # Required for 2FA QR code generation
from PIL import Image # Required by qrcode[pil]
import string
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD

# Set up logging
def setup_logging():
    logging.basicConfig(
        filename=LOG_PATH,
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Also log to console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    # Get the root logger and add the console handler
    root_logger = logging.getLogger()
    # Avoid adding handler multiple times if setup_logging is called more than once
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        root_logger.addHandler(console_handler)
    root_logger.setLevel(logging.INFO) # Set root logger level

# --- Fallback for compare_digest for older Python versions ---
try:
    # Try to get the built-in compare_digest
    _compare_digest = hashlib.compare_digest
except AttributeError:
    # If it doesn't exist, provide a constant-time comparison function
    # This is a common fallback, but the built-in one is preferred if available
    def _safer_compare(a, b):
        """
        Reduces the risk of timing analysis attacks.
        Note: This is a basic implementation. Python's built-in
        hashlib.compare_digest is more robust if available.
        """
        if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
            # For safety, if types are wrong, consider them not equal.
            # Or raise a TypeError. For this context, returning False is safer.
            logging.warning("_safer_compare called with non-byte types.")
            return False

        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    _compare_digest = _safer_compare
    logging.info("Using fallback _safer_compare for hash comparison (Python < 3.3 or missing hashlib.compare_digest).")
# --- End of Fallback ---


# Security utilities
def hash_password(password: str, salt: bytes = None) -> tuple[str, bytes]:
    """Hash a password with salt using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = os.urandom(SALT_LENGTH)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH, # Length of the derived key hash for storage/comparison
        salt=salt,
        iterations=ITERATIONS,
    )

    # The derived key here is the hash to be stored
    key_hash = kdf.derive(password.encode())
    # Store the hash as base64 for easier DB storage
    return base64.b64encode(key_hash).decode('utf-8'), salt

def verify_password(password: str, stored_hash_b64: str, salt: bytes) -> bool:
    """Verify a password against its base64 encoded hash and salt."""
    try:
        # Decode the stored hash from base64
        stored_hash_bytes = base64.b64decode(stored_hash_b64)

        # Derive the hash for the provided password using the stored salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=ITERATIONS,
        )
        derived_hash_bytes = kdf.derive(password.encode())

        # Compare the derived hash with the stored hash using compare_digest for timing safety
        return _compare_digest(derived_hash_bytes, stored_hash_bytes)
    except (base64.binascii.Error, TypeError, ValueError) as e:
        logging.error(f"Error during password verification: {e}")
        return False


def generate_encryption_key_from_password(password: str, salt: bytes) -> bytes:
    """Generate a Fernet-compatible encryption key from a password using PBKDF2."""
    # Use the same salt as the master password hash for key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet requires exactly 32 bytes for the key
        salt=salt,
        iterations=ITERATIONS, # Use the same high iteration count
    )

    # Derive the 32-byte key
    derived_key = kdf.derive(password.encode())
    # Encode it in URL-safe base64 for Fernet
    return base64.urlsafe_b64encode(derived_key)

def encrypt_data(data: bytes, cipher_suite: Fernet) -> Optional[str]:
    """Encrypt data using the provided Fernet cipher suite."""
    try:
        encrypted_data = cipher_suite.encrypt(data)
        return encrypted_data.decode('utf-8') # Store as string
    except Exception as e:
        logging.error(f"Encryption failed: {e}")
        return None

def decrypt_data(encrypted_data_str: str, cipher_suite: Fernet) -> Optional[bytes]:
    """Decrypt data using the provided Fernet cipher suite."""
    try:
        encrypted_data = encrypted_data_str.encode('utf-8')
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data
    except InvalidToken:
        logging.error("Decryption failed: Invalid token (likely wrong key or corrupted data)")
        return None
    except Exception as e:
        logging.error(f"Decryption failed: {e}")
        return None

# Password Strength
def check_password_strength(password: str) -> Dict[str, Any]:
    """Check password strength using zxcvbn."""
    if not password:
        return {"score": 0, "feedback": {"warning": "Password is empty", "suggestions": []}, "strength_description": "Very Weak"}
    try:
        results = zxcvbn.zxcvbn(password)
        # Add a simple description based on score
        score_map = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong"}
        results['strength_description'] = score_map.get(results['score'], "Unknown")
        return results
    except Exception as e:
        logging.error(f"Zxcvbn check failed: {e}")
        return {"score": 0, "feedback": {"warning": "Strength check unavailable", "suggestions": []}, "strength_description": "Unknown"}


# Password Generation
def generate_password(length: int = 16, use_uppercase: bool = True, use_lowercase: bool = True,
                      use_digits: bool = True, use_symbols: bool = True) -> str:
    """Generate a random password with customizable character sets."""
    character_pool = ""
    if use_uppercase:
        character_pool += string.ascii_uppercase
    if use_lowercase:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    # Ensure common, URL-safe symbols. Avoid easily confused chars if needed.
    if use_symbols:
        character_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not character_pool:
        raise ValueError("At least one character set must be selected")
    if length <= 0:
        raise ValueError("Password length must be positive")

    # Ensure at least one character from each selected pool if possible (more robust generation)
    password_chars = []
    guaranteed_chars = 0
    temp_pool = list(character_pool) # Create a mutable list for potential removal

    if use_uppercase and string.ascii_uppercase:
        char = random.choice(string.ascii_uppercase)
        password_chars.append(char)
        guaranteed_chars += 1
        if char in temp_pool : temp_pool.remove(char) # Avoid picking same char for guarantee if pool is small
    if use_lowercase and string.ascii_lowercase:
        char = random.choice(string.ascii_lowercase)
        password_chars.append(char)
        guaranteed_chars += 1
        if char in temp_pool : temp_pool.remove(char)
    if use_digits and string.digits:
        char = random.choice(string.digits)
        password_chars.append(char)
        guaranteed_chars += 1
        if char in temp_pool : temp_pool.remove(char)
    if use_symbols and "!@#$%^&*()_+-=[]{}|;:,.<>?": # Check symbols string is not empty
        char = random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
        password_chars.append(char)
        guaranteed_chars += 1
        if char in temp_pool : temp_pool.remove(char)

    # If character_pool becomes empty after guaranteeing, repopulate it
    # This handles cases where length is small and all chosen characters are unique from the pool
    if not temp_pool and length > guaranteed_chars :
        temp_pool = list(character_pool)


    remaining_length = length - guaranteed_chars
    if remaining_length < 0: # If length is too small for guaranteed chars, take subset
        password_chars = password_chars[:length]
        remaining_length = 0


    if remaining_length > 0:
        # Use the full character_pool for remaining characters to ensure diversity
        # unless it's empty (edge case for very small length and many guaranteed types)
        fill_pool = character_pool if character_pool else temp_pool # Fallback to temp_pool if main is exhausted
        if not fill_pool: # Super edge case, length is 1, only one type allowed. Should be fine.
             pass
        else:
            password_chars.extend(random.choice(fill_pool) for _ in range(remaining_length))


    random.shuffle(password_chars)
    return "".join(password_chars)

# Export / Import Utilities
def export_vault(data: Dict[str, Any], filepath: str, cipher_suite: Fernet) -> bool:
    """Export vault data to an encrypted JSON file."""
    try:
        json_data = json.dumps(data, indent=2).encode('utf-8')
        encrypted_content = encrypt_data(json_data, cipher_suite)
        if encrypted_content is None:
            return False

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(encrypted_content)
        logging.info(f"Vault exported successfully to {filepath}")
        return True
    except (IOError, json.JSONDecodeError, TypeError) as e:
        logging.error(f"Failed to export vault: {e}")
        return False

def import_vault(filepath: str, cipher_suite: Fernet) -> Optional[Dict[str, Any]]:
    """Import vault data from an encrypted JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            encrypted_content = f.read()

        decrypted_json = decrypt_data(encrypted_content, cipher_suite)
        if decrypted_json is None:
            return None # Decryption failed

        data = json.loads(decrypted_json.decode('utf-8'))
        logging.info(f"Vault imported successfully from {filepath}")
        return data
    except (IOError, json.JSONDecodeError, TypeError) as e:
        logging.error(f"Failed to import vault: {e}")
        return None
    except FileNotFoundError:
        logging.error(f"Import file not found: {filepath}")
        return None

# Clipboard Management
_clipboard_timer = None
_clipboard_content = None

def copy_to_clipboard_timed(text: str, timeout_seconds: int):
    """Copy text to clipboard and schedule it to be cleared."""
    global _clipboard_timer, _clipboard_content
    try:
        import pyperclip
        pyperclip.copy(text)
        _clipboard_content = text # Store what was copied
        logging.info(f"Copied text to clipboard. Will clear in {timeout_seconds}s.")

        # Cancel previous timer if any
        if _clipboard_timer and _clipboard_timer.is_alive():
            _clipboard_timer.cancel()

        # Start a new timer
        from threading import Timer
        _clipboard_timer = Timer(timeout_seconds, clear_clipboard_if_match, [text])
        _clipboard_timer.daemon = True # Allow program to exit even if timer is running
        _clipboard_timer.start()
    except ImportError:
        logging.warning("pyperclip not installed. Cannot copy to clipboard.")
    except Exception as e:
        logging.error(f"Failed to copy to clipboard: {e}")


def clear_clipboard_if_match(original_content: str):
    """Clear the clipboard only if it still contains the original copied content."""
    global _clipboard_timer, _clipboard_content
    try:
        import pyperclip
        current_clipboard = pyperclip.paste()
        # Check if the clipboard content is still what we copied
        if current_clipboard == original_content:
            pyperclip.copy('') # Clear clipboard
            logging.info("Clipboard cleared automatically.")
        else:
            logging.info("Clipboard content changed, not clearing.")
    except ImportError:
        pass # Ignore if pyperclip is not available
    except Exception as e:
        logging.error(f"Failed to clear clipboard: {e}")
    finally:
         _clipboard_timer = None
         _clipboard_content = None # Clear tracked content


# --- 2FA Utilities ---
def generate_totp_secret() -> str:
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer_name: str) -> str:
    """Generate a TOTP provisioning URI (for QR code)."""
    # Ensure username is URL-encoded if it contains special characters
    from urllib.parse import quote
    accountname = quote(username)
    issuer = quote(issuer_name)
    return pyotp.totp.TOTP(secret).provisioning_uri(name=accountname, issuer_name=issuer)

def verify_totp_code(secret: str, code: str) -> bool:
    """Verify a TOTP code against the secret."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

def generate_qr_code_image(uri: str, filename: str = "totp_qr.png") -> Optional[str]:
    """Generate a QR code image for the TOTP URI and save it."""
    try:
        img = qrcode.make(uri)
        # Ensure DATA_DIR exists for saving QR code
        if not DATA_DIR.exists():
            DATA_DIR.mkdir(parents=True, exist_ok=True)
        filepath = DATA_DIR / filename
        img.save(filepath)
        logging.info(f"Generated QR code image: {filepath}")
        return str(filepath)
    except Exception as e:
        logging.error(f"Failed to generate QR code: {e}")
        return None

def send_otp_email(recipient_email: str, otp_code: str, subject: str = "Your OTP Code", body: str = None) -> bool:
    """Send an OTP code to the specified email address using SMTP."""
    if body is None:
        body = f"Your one-time password (OTP) is: {otp_code}\n\nIf you did not request this, please ignore this email."
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = recipient_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        logging.info(f"OTP email sent to {recipient_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send OTP email to {recipient_email}: {e}")
        return False