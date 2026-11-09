"""Protected assets: logos and marketing images with a hidden serial number (OpenCV/NumPy LSB, src/stego.py)."""
import os

from src import db, security, stego
from src.documents import upload_dir

ALLOWED = {"png", "jpg"}


def protect_asset(company_id, filename, data):
    """Embeds a new serial in the image, stores the marked PNG and records serial + hashes.
    Returns {"id", "serial", "sha256"}; raises ValueError with a user-safe message."""
    if not data:
        raise ValueError("Choose an image to protect.")
    if len(data) > security.MAX_FILE_BYTES:
        raise ValueError("That file is larger than 8 MB.")
    if security.sniff(data) not in ALLOWED:
        raise ValueError("Only PNG and JPG images can be protected.")
    serial = security.new_serial()
    try:
        marked = stego.embed_serial(data, serial)
    except stego.StegoError as e:
        raise ValueError(str(e))
    rel = f"{company_id}/assets/{serial}.png"
    path = os.path.join(upload_dir(), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(marked)
    try:
        asset_id = db.add_asset(company_id, security.clean_name(filename), rel, serial, security.sha256_hex(data),
                                security.sha256_hex(marked), len(marked))
    except ValueError:
        os.remove(path)
        raise
    return {"id": asset_id, "serial": serial, "sha256": security.sha256_hex(marked)}


def check_image(company_id, data):
    """What a company may learn about an image: (serial or None, 'yours' | 'other' | 'none')."""
    serial = stego.extract_serial(data) if data else None
    if not serial:
        return None, "none"
    owner = db.serial_owner(serial)
    if owner is None:
        return None, "none"
    return (serial, "yours") if owner == company_id else (None, "other")
