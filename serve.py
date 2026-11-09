"""Production-style dashboard server that works on Windows, Linux and macOS.
Run:  python serve.py      (HOST / PORT env vars optional; default http://127.0.0.1:8000)"""
import os

from dashboard.app import create_app

app = create_app()

if __name__ == "__main__":
    host, port = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8000"))
    try:
        from waitress import serve
        print(f"Dashboard running on http://{host}:{port}")
        serve(app, host=host, port=port)
    except ImportError:
        app.run(host=host, port=port)
