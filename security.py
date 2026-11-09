"""Shared validation: password policy, KRA PIN format, uploaded-file sniffing, hashing, serial numbers."""
import hashlib
import os
import re
import secrets
from datetime import datetime, timezone

PASSWORD_HINT = "At least 8 characters with an uppercase letter, a lowercase letter and a special character."
KRA_RE = re.compile(r"^P\d{9}[A-Z]$")             # company PINs start with P: P + 9 digits + letter
MAX_FILE_BYTES = 8 * 1024 * 1024

# doc_type -> (label, allowed file kinds)
DOC_TYPES = {
    "kra_pin_cert": ("KRA PIN certificate", {"pdf", "png", "jpg"}),
    "registration_cert": ("Certificate of incorporation / business registration", {"pdf", "png", "jpg"}),
    "trademark_cert": ("Intellectual property (trademark) registration certificate", {"pdf", "png", "jpg"}),
    "trademark_photo": ("Company name / trademark photo", {"png", "jpg"}),
}
REQUIRED = tuple(DOC_TYPES)
MIME = {"pdf": "application/pdf", "png": "image/png", "jpg": "image/jpeg"}


def password_problem(pw):
    """Return None if the password is acceptable, otherwise a message listing what is missing."""
    missing = []
    if len(pw) < 8:
        missing.append("at least 8 characters")
    if not re.search(r"[A-Z]", pw):
        missing.append("an uppercase letter")
    if not re.search(r"[a-z]", pw):
        missing.append("a lowercase letter")
    if not re.search(r"[^A-Za-z0-9\s]", pw):
        missing.append("a special character")
    if len(pw) > 128:
        missing.append("at most 128 characters")
    return ("Password needs " + ", ".join(missing) + ".") if missing else None


def normalize_kra(pin):
    return (pin or "").strip().upper().replace(" ", "")


def kra_valid(pin):
    return bool(KRA_RE.match(normalize_kra(pin)))


def sniff(data):
    """Identify the real file type from its first bytes (never trust the extension)."""
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    return None


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def new_serial():
    """Key serial number recorded with the file hash, e.g. RGD-2026-9F3A1C7E."""
    return f"RGD-{datetime.now(timezone.utc).year}-{secrets.token_hex(4).upper()}"


def clean_name(name):
    base = os.path.basename(name or "file").replace("\\", "/").split("/")[-1]
    return re.sub(r"[^A-Za-z0-9._ -]", "_", base)[:120] or "file"
