"""Celery application: Redis is the message broker and result store. Workers run the heavy jobs (browser
evidence collection, report emails) so the stream listener and the website never block.

Start a worker:  celery -A src.celery_app.celery worker --loglevel=info --concurrency=3
Start the clock: celery -A src.celery_app.celery beat --loglevel=info
For development without Redis set CELERY_ALWAYS_EAGER=true (tasks then run immediately in-process)."""
import os

from celery import Celery

BROKER = os.getenv("REDIS_URL", "redis://localhost:6379/0")
EAGER = os.getenv("CELERY_ALWAYS_EAGER", "false").lower() == "true"

celery = Celery("rorgid", broker=BROKER, backend=BROKER)
celery.conf.update(
    imports=("src.workers.tasks",),
    task_serializer="json", accept_content=["json"], result_serializer="json",
    task_acks_late=True,                        # a task lost with a crashed worker is run again
    worker_prefetch_multiplier=1,               # one slow browser job must not hide a queue of others
    task_time_limit=int(os.getenv("TASK_TIME_LIMIT", "180")),
    task_soft_time_limit=int(os.getenv("TASK_SOFT_TIME_LIMIT", "150")),
    result_expires=3600, timezone="UTC", enable_utc=True,
    broker_connection_retry_on_startup=True,
    broker_transport_options={"socket_connect_timeout": 3, "socket_timeout": 5},   # fail fast if Redis is unreachable
    task_publish_retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.2, "interval_max": 0.5},
    task_always_eager=EAGER, task_eager_propagates=EAGER,
    beat_schedule={"sweep-approved-reports": {"task": "rorgid.sweep_reports",
                                              "schedule": float(os.getenv("REPORT_POLL_SECONDS", "60"))}},
)
