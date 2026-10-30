"""
Bootstrap script — creates the first IT Admin account and organization.

Usage (inside the running API container):
  docker compose exec api python -m app.scripts.create_admin

Or with args:
  docker compose exec api python -m app.scripts.create_admin \
    --email admin@company.com \
    --username "IT Admin" \
    --org "Acme Corp" \
    --password "changeme123"
"""
import asyncio
import argparse
import sys
import getpass

from sqlalchemy import select, func


async def _create(email: str, username: str, password: str, org_name: str):
    # Import here so the script can be run standalone
    from app.db.session import AsyncSessionLocal
    from app.models.models import User, Organization, UserRole
    from app.core.auth import hash_password


    async with AsyncSessionLocal() as db:
        # Check if any user already exists
        count = (await db.execute(select(func.count()).select_from(User))).scalar()
        if count > 0:
            print(f"\n⚠️  Users already exist ({count} total).")
            print("   Use the dashboard to create additional users.")
            print("   To reset, clear the database first.\n")
            sys.exit(1)

        # Create org
        import re
        slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")[:50]
        org = Organization(name=org_name, slug=slug)
        db.add(org)
        await db.flush()

        # Create admin user
        user = User(
            organization_id=org.id,
            email=email,
            username=username,
            hashed_password=hash_password(password),
            role=UserRole.IT_ADMIN,
            is_active=True,
        )
        db.add(user)
        await db.commit()

        print(f"\n✅  Admin account created successfully!")
        print(f"    Organization : {org_name}")
        print(f"    Email        : {email}")
        print(f"    Role         : IT Admin")
        print(f"\n    Log in at your NetAudit dashboard URL.\n")


def main():
    parser = argparse.ArgumentParser(description="Create the first NetAudit admin account")
    parser.add_argument("--email", help="Admin email address")
    parser.add_argument("--username", help="Display name", default="IT Admin")
    parser.add_argument("--org", help="Organization name", default="My Organization")
    parser.add_argument("--password", help="Password (prompted if omitted)")
    args = parser.parse_args()

    # Prompt for missing values interactively
    email = args.email or input("Admin email: ").strip()
    username = args.username
    org_name = args.org

    if not email:
        print("Email is required.")
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            sys.exit(1)

    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)

    asyncio.run(_create(email, username, password, org_name))


if __name__ == "__main__":
    main()
