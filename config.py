"""Engine settings. Brands and domains now come from verified companies in the database, not from here."""
import os
from types import SimpleNamespace

settings = SimpleNamespace(PROJECT_NAME=os.getenv("PROJECT_NAME", "RORGID Brand Protection Engine"))
