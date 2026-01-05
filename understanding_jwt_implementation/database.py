"""
Fake Database
In production, replace with SQLAlchemy + PostgreSQL/MySQL
"""

from passlib.context import CryptContext

# Password hashing setup
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# FAKE USERS DATABASE
# Key: username, Value: user data
fake_users_db = {
    "usman": {
        "user_id": 101,
        "username": "usman",
        "email": "usman@example.com",
        "full_name": "Usman Khan",
        "hashed_password": pwd_context.hash("secret123"),  # Password: secret123
        "disabled": False,
    },
    "alice": {
        "user_id": 102,
        "username": "alice",
        "email": "alice@example.com",
        "full_name": "Alice Smith",
        "hashed_password": pwd_context.hash("alicepass"),  # Password: alicepass
        "disabled": False,
    },
    "disabled_user": {
        "user_id": 103,
        "username": "disabled_user",
        "email": "disabled@example.com",
        "full_name": "Disabled User",
        "hashed_password": pwd_context.hash("test123"),
        "disabled": True,  # This user cannot login
    }
}