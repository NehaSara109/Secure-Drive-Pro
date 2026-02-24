import jwt
import os
from datetime import datetime, timedelta
from jwt import ExpiredSignatureError, InvalidTokenError

SECRET = os.getenv("JWT_SECRET_KEY", "dev-jwt-secret-change-me")

def generate_token(username, role):
    payload = {
        "user": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=30)
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")

def verify_token(token):
    if not token:
        return None

    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except (ExpiredSignatureError, InvalidTokenError, TypeError, ValueError):
        return None
