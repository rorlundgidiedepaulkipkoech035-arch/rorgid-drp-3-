# What has to be done to complete the platform

Status after this build (8 November 2026). "Tested here" means the code was run in the development
environment. "Built, not run" means it is written but could not be executed there (the libraries or services
were not available). GitHub Actions is set up to run those parts as soon as you push.

## 1. Your eight technology layers

| # | Layer | Status |
|---|-------|--------|
| 1 | Python asyncio | Built and tested. The engine (main.py), the evidence pipeline and the scraper are asyncio programs. |
| 2 | Certstream, regular expressions, Levenshtein | Detection rules built and tested (22/22 test domains). Live certstream connection: built, not run. |
| 3 | Playwright (async) and hashlib SHA-256 | Built. Hashing and the safety checks are tested; the browser part is not run (no browser here). |
| 4 | OpenCV and NumPy LSB steganography | Built and tested (12 tests on real images). Limits explained in section 4. |
| 5 | Celery and Redis | Built. Tested here in eager mode (tasks run immediately). A real worker with Redis is checked by the GitHub integration job: not run yet. |
| 6 | PostgreSQL and SQLAlchemy | Built. Tested here through a reference copy of the data layer with identical contract tests. The SQLAlchemy layer itself is checked by GitHub on SQLite and on PostgreSQL: not run yet. |
| 7 | smtplib and email MIME | Built and unit-tested with a fake mail server. Real sending: not run. |
| 8 | Docker and Docker Compose | Written (PostgreSQL, Redis, web, engine, worker, beat, one-time database setup). The compose file is validated by GitHub; images were never built. |

## 2. Phase 0: first run and fixes (do this first)

1. Upload the project to a private GitHub repository.
2. Open the Actions tab. Two jobs run: **unit** (real SQLAlchemy and Celery, eager) and **integration**
   (PostgreSQL, Redis, a real Celery worker, compose file check).
3. Expect a few failures the first time, because the SQLAlchemy, Celery and Docker parts have never been
   executed. Send me the red error text and I will fix each one. Do not skip this step.
4. On a computer or server with Docker: `cp .env.example .env`, fill it in, `docker compose up -d --build`,
   then `docker compose ps` (every service Up) and `docker compose logs worker engine`.
5. Log in at http://localhost:8000 with ADMIN_EMAIL / ADMIN_PASSWORD, register a test company, verify it.

## 3. Phase 1: prove the real pipeline with real services

- Buy or use a cheap test domain that looks like your test brand, get a real certificate for it, and confirm
  the engine flags it from the live certificate feed (the free public certstream server is often down; run
  your own certstream server).
- Confirm the Playwright worker captures a screenshot and the HTML of that test site, and that SHA-256 hashes
  match the saved files.
- Send a real reset-code email and a real takedown email to a mailbox you control.
- Ask KE-CIRT/CC for the official reporting address and the format they want (evidence, hashes, wording), then
  set KECIRT_REPORT_TO and adjust the email text.
- Run a short soak test: leave the stack running for 24 hours and check logs, memory, queue length and
  database size.

## 4. Phase 2: watermark quality

LSB marks survive byte-for-byte copies and lossless re-saves of a PNG. They do not survive JPEG/WebP
re-compression, resizing, cropping or screenshots. To finish this layer:

- Add perceptual hashing (pHash/dHash) so resized or re-compressed copies of a logo are still matched.
- Add a frequency-domain watermark (DCT or wavelet) for assets that will be compressed or resized.
- Decide the policy for the secret STEGO_KEY: store it safely, back it up, never change it (changing it makes
  every earlier mark unreadable).
- Test with real copies: download a protected logo through a CDN, a social network and a browser, and measure
  what survives.

## 5. Phase 3: security and production hardening

- HTTPS in front of the website (Caddy or nginx), COOKIE_SECURE=true, a real domain.
- Prove domain ownership with a DNS TXT record per company domain.
- Platform admin reviews each new company’s documents (automatic verification cannot prove they are genuine).
- Two-factor login for platform and company admins.
- Move login throttling to Redis (it is per process now) and add rate limits on registration and reset codes.
- Replace create_all with Alembic migrations before the first real customer.
- Backups: PostgreSQL (pg_dump on a schedule), the uploads and artifacts volume, and a tested restore.
- Pin exact package versions, scan for vulnerable packages, run containers as a non-root user, and get an
  independent security review of the upload handling, the scraper and the password reset.
- Admin screens for the audit log, user management and deleting a company.

## 6. Phase 4: detection and reporting quality

- Index brands so matching stays fast with thousands of companies (today every name is compared with every
  company).
- Keep a per-company list of false positives so analysts do not see them again.
- Add registrar/hosting abuse notices (look up the abuse contact with RDAP) in addition to KE-CIRT/CC, each
  behind company-admin approval.
- Follow redirects safely, record certificate details and domain age, and add a "still online?" re-check.
- Case export: one PDF per finding with screenshot, HTML hash manifest and timeline.

## 7. Phase 5: product, legal and operations

- Email and in-app alerts for new findings; weekly summary to company admins.
- Plans and billing, terms of service, privacy notice, and a data retention policy.
- Check obligations under the Kenya Data Protection Act, 2019 with a lawyer (documents and staff emails are
  personal data), and agree liability for false positives and takedown requests.
- Monitoring and alerts (queue length, worker failures, disk, certificate feed status), a staging environment,
  automatic deployment, and a written runbook.
- Load test with the real certificate volume.

## 8. Suggested order

Phase 0, then Phase 1, then the High items of Phase 3, then Phase 2. Do not onboard a paying company before
Phases 0, 1 and the Phase 3 items (HTTPS, backups, admin review, domain proof) are done.
