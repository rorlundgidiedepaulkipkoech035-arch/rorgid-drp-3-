"""Stores a verification document: checks it, hashes it, issues a key serial number and records both."""
import os

from src import db, security


def upload_dir():
    return os.path.abspath(os.getenv("UPLOAD_DIR", "./uploads"))


def store_document(company_id, doc_type, filename, data):
    """Returns {"serial", "sha256", "kind"}; raises ValueError with a user-safe message."""
    if doc_type not in security.DOC_TYPES:
        raise ValueError("Unknown document type.")
    if not data:
        raise ValueError("Choose a file to upload.")
    if len(data) > security.MAX_FILE_BYTES:
        raise ValueError("That file is larger than 8 MB.")
    kind = security.sniff(data)
    allowed = security.DOC_TYPES[doc_type][1]
    if kind not in allowed:
        raise ValueError("Unsupported file. Allowed: " + ", ".join(sorted(x.upper() for x in allowed)) + ".")
    digest, serial = security.sha256_hex(data), security.new_serial()
    rel = f"{company_id}/{digest}.{kind}"
    path = os.path.join(upload_dir(), rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    existed = os.path.exists(path)
    with open(path, "wb") as f:
        f.write(data)
    try:
        _, old = db.save_document(company_id, doc_type, security.clean_name(filename), rel,
                                  security.MIME[kind], len(data), digest, serial)
    except ValueError:
        if not existed:
            os.remove(path)
        raise
    for name in old:                       # replaced document: remove the old stored file
        if name != rel:
            try:
                os.remove(os.path.join(upload_dir(), name))
            except OSError:
                pass
    return {"serial": serial, "sha256": digest, "kind": kind}
