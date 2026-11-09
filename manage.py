"""Usage: python -m dashboard.manage create-admin you@example.com"""
import getpass
import sys

from werkzeug.security import generate_password_hash

from src import db, security

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "create-admin":
        sys.exit(__doc__)
    db.init_db()
    pw = getpass.getpass("Password: ")
    problem = security.password_problem(pw)
    if problem:
        sys.exit(problem)
    db.create_user(None, sys.argv[2].lower(), generate_password_hash(pw), "platform_admin")
    print("Platform admin created.")
