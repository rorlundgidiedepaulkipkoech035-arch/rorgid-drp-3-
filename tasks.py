"""Celery tasks. Task names are fixed strings so the engine, the website and the workers always agree."""
import asyncio
import logging

from src import db, pipeline, reporting
from src.celery_app import celery

log = logging.getLogger("DRP-Tasks")


@celery.task(name="rorgid.ping")
def ping_task():
    return "pong"


@celery.task(name="rorgid.handle_threat", bind=True, max_retries=2)
def handle_threat_task(self, domain, reason, company_id, company_auto_report=False):
    """Evidence collection for one flagged domain. Unexpected crashes are retried twice, a minute apart."""
    try:
        return asyncio.run(pipeline.handle_threat(domain, reason, company_id, company_auto_report))
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)


@celery.task(name="rorgid.send_report")
def send_report_task(finding_id):
    """Sends one approved report. claim_report() lets exactly one worker win, so nothing is sent twice."""
    if not db.claim_report(finding_id):
        return "skipped"
    finding = db.get_finding_any(finding_id)
    ok = reporting.send_finding_report(finding)
    db.mark_reported(finding_id, ok)
    return "sent" if ok else "failed"


@celery.task(name="rorgid.sweep_reports")
def sweep_reports_task():
    """Safety net run by Celery beat: re-queue stuck sends and pick up approvals whose message was lost."""
    requeued = db.requeue_stale_reports()
    pending = db.fetch_approved_findings()
    for f in pending:
        send_report_task.delay(f["id"])
    return {"requeued": requeued, "queued": len(pending)}
