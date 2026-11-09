#!/usr/bin/env bash
# Single-container development stack (Codespaces / your own computer): SQLite + Celery in eager mode, no Redis needed.
# For the full stack (PostgreSQL + Redis + worker) use:  docker compose up -d --build
set -e
python bootstrap.py
( while true; do python main.py >> engine.log 2>&1; echo "engine stopped, restarting in 5s" >> engine.log; sleep 5; done ) &
exec python serve.py
