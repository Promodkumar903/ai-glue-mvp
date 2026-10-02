
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from config import Config
from models import User, db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(user_id):
    payload = {
        'sub': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

def decode_token(token):
    try:
        return jwt.decode(token, Config.SECRET_KEY, algorithms=['HS256'])
    except:
        return None

def get_user_by_username(username):
    return User.query.filter_by(username=username).first()

def create_user(username, password):
    if get_user_by_username(username):
        return None
    user = User(username=username, password_hash=hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user
