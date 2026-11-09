"""Loads approved companies/brands/domains from the DB and evaluates domains against all of them."""
import logging
import os
import threading
import time
from collections import namedtuple

from src import db
from src.detection import assess_domain

logger = logging.getLogger("DRP-Tenants")
Hit = namedtuple("Hit", "company_id reason auto_report")


class TenantRegistry:
    def __init__(self, ttl=None, loader=db.registry_snapshot):
        self.ttl = ttl if ttl is not None else int(os.getenv("REGISTRY_REFRESH_SECONDS", "60"))
        self._loader = loader
        self._tenants, self._loaded = [], 0.0
        self._lock = threading.Lock()
        self.auto_refresh = True      # the asyncio engine turns this off and calls reload() from a background task

    def invalidate(self):
        self._loaded = 0.0

    def reload(self):
        with self._lock:
            self._loaded = 0.0
        self._refresh(force=True)

    def _refresh(self, force=False):
        with self._lock:
            if not force and time.time() - self._loaded < self.ttl:
                return
            try:
                self._tenants = self._loader()
            except Exception as e:  # keep serving the last good snapshot
                logger.error(f"[-] Could not reload tenants: {e!r}")
            self._loaded = time.time()

    def evaluate(self, domain):
        if self.auto_refresh:
            self._refresh()
        for t in self._tenants:
            reason = assess_domain(domain, t["brands"], t["domains"])
            if reason:
                yield Hit(t["company_id"], reason, t["auto_report"])
