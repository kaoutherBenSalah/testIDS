import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from models import get_user_by_username, verify_password, load_users_db

print("=" * 60)
print("Testing User Credentials")
print("=" * 60)

users_db = load_users_db()
print(f"\nUsers in database: {list(users_db.keys())}")

for username in ['defender', 'attacker']:
    print(f"\n{username}:")
    print(f"  - Exists: {username in users_db}")
    if username in users_db:
        print(f"  - Role: {users_db[username]['role']}")
        test_pass = 'defend123' if username == 'defender' else 'attack123'
        valid = verify_password(username, test_pass)
        print(f"  - Password valid: {valid}")

print("\n" + "=" * 60)
print("Make sure to login as 'defender' with password 'defend123'")
print("=" * 60)
