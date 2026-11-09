"""Proves that Redis, the Celery worker and the task code are connected: sends a ping task and waits for the answer."""
import sys

from src.workers.tasks import ping_task

result = ping_task.delay().get(timeout=30)
print("worker answered:", result)
sys.exit(0 if result == "pong" else 1)
