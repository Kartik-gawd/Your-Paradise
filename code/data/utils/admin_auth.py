import hashlib
import secrets
import threading

ADMIN_PASSWORD_HASH:   bytes = b""
ADMIN_SESSION_SECRET:  str   = secrets.token_urlsafe(32)
ADMIN_CSRF_TOKEN:      str   = secrets.token_urlsafe(32)

def set_password_hash(raw_password: str) -> None:
    global ADMIN_PASSWORD_HASH
    ADMIN_PASSWORD_HASH = hashlib.sha256(raw_password.encode()).digest()

def _verify_password(submitted: str) -> bool:
    submitted_hash = hashlib.sha256(submitted.encode()).digest()
    return secrets.compare_digest(ADMIN_PASSWORD_HASH, submitted_hash)

def _get_cookie(handler, name: str) -> str:
    for part in handler.headers.get("Cookie", "").split(";"):
        part = part.strip()
        if part.startswith(f"{name}="):
            return part[len(f"{name}="):]
    return ""

def check_admin_session_only(handler) -> bool:
    if hasattr(handler, "is_admin") and handler.is_admin():
        return True
    val = _get_cookie(handler, "admin_session")
    return bool(val) and secrets.compare_digest(val, ADMIN_SESSION_SECRET)

def check_admin_auth(handler) -> bool:
    session_val = _get_cookie(handler, "admin_session")
    csrf_header = handler.headers.get("X-Admin-CSRF", "")
    if session_val and secrets.compare_digest(session_val, ADMIN_SESSION_SECRET) and \
       csrf_header and secrets.compare_digest(csrf_header, ADMIN_CSRF_TOKEN):
        return True
    if hasattr(handler, "is_admin") and handler.is_admin():
        return True
    return False
