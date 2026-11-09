# RORGID Brand Protection Platform

Digital Risk Protection (DRP) and brand-takedown pipeline.

| Layer | Technology |
|-------|------------|
| Language | Python 3.12 with asyncio |
| Discovery | certstream (Certificate Transparency), regular expressions, Levenshtein distance |
| Evidence | Playwright (async API, headless Chromium), hashlib SHA-256 |
| Forensics | OpenCV + NumPy, LSB steganography for serial numbers hidden in logos and marketing assets |
| Queue | Celery workers, Redis broker |
| Storage | PostgreSQL through SQLAlchemy 2 (SQLite for development and tests) |
| Reporting | smtplib and email MIME to KE-CIRT/CC |
| Deployment | Docker and Docker Compose |

## Run the full stack (PostgreSQL + Redis + web + engine + worker + beat)
    cp .env.example .env        # fill it in; never commit it
    docker compose up -d --build
    open http://localhost:8000

## Try it without Docker (fake data, SQLite, no Redis)
    pip install -r requirements.txt
    python demo.py                # http://127.0.0.1:5000
    python demo_backend.py        # back-end walk-through in the terminal (34 checks)
    python detection_check.py     # detection test with a fake company (22 domains)

## Tests (each file runs on its own)
    python test_stego.py ; python test_db.py ; python test_drp.py
    python test_dashboard.py ; python test_workers.py

See RUN_REAL.md (step by step), COMPLETION_PLAN.md (what is left to do) and the PDF documentation.
