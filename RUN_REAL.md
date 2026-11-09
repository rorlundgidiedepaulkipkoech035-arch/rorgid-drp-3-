# Run the real system

There are two ways. Pick one.

## A. The full stack with Docker (PostgreSQL + Redis + worker). Use this for the real thing.
You need a computer or rented server with Docker installed (Docker Desktop on Windows/Mac).

1. Copy `.env.example` to `.env` and open it in a text editor.
2. Fill in every line:
   - POSTGRES_PASSWORD: letters and digits only.
   - SECRET_KEY and STEGO_KEY: two different long random texts (40+ characters). Keep STEGO_KEY forever; if
     you change it, hidden marks in earlier logos can no longer be read.
   - ADMIN_EMAIL and ADMIN_PASSWORD: your platform-admin login (8+ characters, upper, lower, special).
   - SMTP_*: the email account that sends reset codes and reports (use an app password).
   - KECIRT_REPORT_TO: the official KE-CIRT/CC reporting address.
3. In a terminal inside the project folder run:
       docker compose up -d --build
   The first build takes several minutes (it downloads a browser for evidence screenshots).
4. Check: `docker compose ps` should show every service Up. Open http://localhost:8000 and log in.
5. Watch the engine and worker: `docker compose logs -f engine worker`.
6. Stop: `docker compose down`. Your data stays in Docker volumes (`docker compose down -v` deletes it).

For a public server put HTTPS in front (Caddy is simplest) and set `COOKIE_SECURE=true` in `.env`.

## B. GitHub Codespaces (a test run of the real code, not a 24/7 server)
This uses SQLite and runs Celery tasks immediately, so no PostgreSQL or Redis is needed.

1. Upload the project to a private GitHub repository (check `.devcontainer`, `.github`, `src`, `dashboard`,
   `scripts` are all there).
2. GitHub > profile picture > Settings > Codespaces > Secrets: add SECRET_KEY, STEGO_KEY, ADMIN_EMAIL,
   ADMIN_PASSWORD, SMTP_SERVER, SMTP_SENDER, SMTP_PASSWORD, KECIRT_REPORT_TO for this repository.
3. Repository > Code > Codespaces > Create codespace on main. After 5 to 10 minutes the login page opens
   (or use the Ports tab, port 8000).
4. A codespace stops when idle. Use it to test, not to run continuously.

## Automatic tests on GitHub
Every push runs the **unit** job and the **integration** job (PostgreSQL, Redis and a real Celery worker).
Open the Actions tab. If anything is red, send me the error text.
