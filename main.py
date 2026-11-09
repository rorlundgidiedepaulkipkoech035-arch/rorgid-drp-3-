"""Detection engine: an asyncio program that reads the Certificate Transparency stream and hands every flagged
domain to a Celery worker through Redis.

  certstream (WebSocket, runs in a thread) -> asyncio.Queue -> detection rules (src/detection.py)
      -> Celery task "rorgid.handle_threat" -> worker: Playwright evidence + stego check -> PostgreSQL

The engine itself never opens a browser or sends email, so it keeps up with the stream.
"""
import asyncio
import logging
import os
import threading
import time
from collections import OrderedDict

import certstream

from src import db
from src.config import settings
from src.tenants import TenantRegistry

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("DRP-Engine")

CERTSTREAM_URL = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
QUEUE_MAX = int(os.getenv("STREAM_QUEUE_MAX", "20000"))
SEEN_CACHE_SIZE = int(os.getenv("SEEN_CACHE_SIZE", "50000"))
REFRESH_SECONDS = int(os.getenv("REGISTRY_REFRESH_SECONDS", "60"))

registry = TenantRegistry()
_seen = OrderedDict()                              # only touched by the asyncio thread, so no lock is needed
stats = {"messages": 0, "flagged": 0, "dispatched": 0, "dropped": 0, "dispatch_errors": 0}


def dispatch(domain, reason, company_id, company_auto_report):
    """Queues the evidence job on Celery (a network call to Redis, so it is run in a thread)."""
    from src.workers.tasks import handle_threat_task
    handle_threat_task.delay(domain, reason, company_id, company_auto_report)


def _already_seen(key):
    if key in _seen:
        _seen.move_to_end(key)
        return True
    _seen[key] = time.time()
    if len(_seen) > SEEN_CACHE_SIZE:
        _seen.popitem(last=False)
    return False


def domains_in(message):
    if message.get("message_type") != "certificate_update":
        return []
    names = message.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
    return [n.lower().lstrip("*.") for n in names if n]


async def handle_message(message, dispatch_fn=None):
    """Evaluates one certificate message and queues a job for every new (company, domain) match."""
    dispatch_fn = dispatch_fn or dispatch
    stats["messages"] += 1
    for domain in domains_in(message):
        for hit in registry.evaluate(domain):
            key = (hit.company_id, domain)
            if _already_seen(key):
                continue
            stats["flagged"] += 1
            logger.warning("[!] POTENTIAL INFRINGEMENT: %s -> company %s (%s)", domain, hit.company_id, hit.reason)
            try:
                await asyncio.to_thread(dispatch_fn, domain, hit.reason, hit.company_id, hit.auto_report)
                stats["dispatched"] += 1
            except Exception as e:                  # for example Redis is down: forget it so a later sighting retries
                stats["dispatch_errors"] += 1
                _seen.pop(key, None)
                logger.error("[-] Could not queue %s: %r", domain, e)


async def consume(queue, dispatch_fn=None):
    while True:
        message = await queue.get()
        try:
            await handle_message(message, dispatch_fn)
        except Exception as e:
            logger.error("[-] Error processing certificate message: %r", e)


async def housekeeping():
    """Reloads companies/brands/domains in the background and logs a status line every minute."""
    while True:
        await asyncio.sleep(REFRESH_SECONDS)
        await asyncio.to_thread(registry.reload)
        logger.info("[*] engine status: %s", stats)


def _offer(queue, message):
    try:
        queue.put_nowait(message)
    except asyncio.QueueFull:
        stats["dropped"] += 1
        if stats["dropped"] % 1000 == 1:
            logger.warning("[!] Stream queue is full; dropped %s messages so far", stats["dropped"])


def listen_forever(loop, queue):
    """Runs in a thread: certstream's client is blocking, so it hands messages to the asyncio loop."""
    def callback(message, context):
        loop.call_soon_threadsafe(_offer, queue, message)
    backoff = 1
    while True:
        try:
            certstream.listen_for_events(callback, url=CERTSTREAM_URL)
            backoff = 1
        except Exception as e:
            logger.error("[-] Certstream connection lost: %r; retrying in %ss", e, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


async def run():
    loop = asyncio.get_running_loop()
    queue = asyncio.Queue(maxsize=QUEUE_MAX)
    threading.Thread(target=listen_forever, args=(loop, queue), name="certstream", daemon=True).start()
    logger.info("[*] %s listening to %s", settings.PROJECT_NAME, CERTSTREAM_URL)
    await asyncio.gather(consume(queue), housekeeping())


def start_engine():
    db.init_db()
    registry.auto_refresh = False                   # the housekeeping task reloads; detection never waits on the database
    registry.reload()
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("[*] Shutting down the engine.")


if __name__ == "__main__":
    start_engine()
