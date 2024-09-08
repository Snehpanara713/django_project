import jwt
from datetime import datetime, timedelta
from django.conf import settings
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

def create_custom_jwt_token(user):
    payload = {
        'user_id': user.user_id,
        'email_id': user.email_id,
        'exp': datetime.utcnow() + timedelta(minutes=10),
        'iat': datetime.utcnow(),
        'token_type': 'reset_password'
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token

def decode_custom_jwt_token(token):
    try:
        print(f"Decoding token: {token}")
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        print(f"Decoded payload: {payload}")
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token error: {str(e)}")
        return None

def create_custom_jwt_token_for_login(user):
    payload = {
        'user_id': user.user_id,
        'email_id': user.email_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow(),
        'token_type': 'login'
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
    return token