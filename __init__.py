"""Call install() before importing anything from src. It swaps in test doubles ONLY for libraries that are not
installed (SQLAlchemy -> reference sqlite3 layer, Celery -> fake). On a machine or CI job with the real libraries
installed, nothing is swapped and the real SQLAlchemy and Celery code is tested."""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
USING = {"db": "sqlalchemy", "celery": "celery"}


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def install():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    os.environ.setdefault("ALLOW_DB_RESET", "true")
    if importlib.util.find_spec("sqlalchemy") is None and "src.db" not in sys.modules:
        import src
        src.db = _load("src.db", os.path.join(HERE, "reference_db.py"))
        USING["db"] = "reference sqlite3 layer (SQLAlchemy not installed)"
    if importlib.util.find_spec("celery") is None and "celery" not in sys.modules:
        _load("celery", os.path.join(HERE, "fake_celery.py"))
        USING["celery"] = "fake Celery (Celery not installed)"
    return dict(USING)
