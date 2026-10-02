import os

class Config:
    SECRET_KEY = 'super-secret-key-mission-control'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ai_glue.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_EXPIRY_HOURS = 24
    SANDBOX_TIMEOUT = 5
    HIGH_RISK_KEYWORDS = ['delete', 'drop', 'rm -rf', 'format', 'sudo', 'shutdown']
    MEDIUM_RISK_KEYWORDS = ['api', 'database', 'config', 'password', 'secret']