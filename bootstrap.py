"""Creates your platform-admin login from ADMIN_EMAIL / ADMIN_PASSWORD (for Codespaces and servers)."""
import os

from werkzeug.security import generate_password_hash

from src import db, security


def main():
    db.init_db()
    email, pw = os.getenv("ADMIN_EMAIL", "").strip().lower(), os.getenv("ADMIN_PASSWORD", "")
    if not email or not pw:
        print("ADMIN_EMAIL / ADMIN_PASSWORD not set: skipping admin creation.")
    elif db.get_user_by_email(email):
        print(f"Platform admin {email} already exists.")
    elif security.password_problem(pw):
        raise SystemExit(f"ADMIN_PASSWORD rejected: {security.password_problem(pw)}")
    else:
        db.create_user(None, email, generate_password_hash(pw), "platform_admin")
        print(f"Platform admin {email} created.")


if __name__ == "__main__":
    main()
