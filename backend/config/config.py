# ============================================================
# backend/config/config.py
# Application Configuration
# ============================================================
import os
from datetime import timedelta


class Config:
    """Base configuration class."""

    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cyber-ai-super-secret-key-2024-change-in-production')
    DEBUG = False
    TESTING = False

    # JWT
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-cyber-ai-secret-2024')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

    # MySQL Database
    MYSQL_HOST = os.environ.get('MYSQL_HOST', 'localhost')
    MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
    MYSQL_USER = os.environ.get('MYSQL_USER', 'root')
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'password')
    MYSQL_DB = os.environ.get('MYSQL_DB', 'cyber_ai_db')

    # SQLAlchemy URI (fallback to SQLite for demo without MySQL)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        f"mysql+pymysql://{os.environ.get('MYSQL_USER','root')}:{os.environ.get('MYSQL_PASSWORD','password')}"
        f"@{os.environ.get('MYSQL_HOST','localhost')}/{os.environ.get('MYSQL_DB','cyber_ai_db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_POOL_RECYCLE = 280
    SQLALCHEMY_POOL_TIMEOUT = 20

    # ML Model
    MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_model', 'model.pkl')
    SCALER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_model', 'scaler.pkl')
    ENCODER_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_model', 'encoder.pkl')

    # Security
    BRUTE_FORCE_THRESHOLD = 5       # failed attempts before blocking
    BRUTE_FORCE_WINDOW = 300        # seconds (5 minutes)
    RISK_SCORE_HIGH = 75.0
    RISK_SCORE_MEDIUM = 40.0

    # Email Alerts (simulation)
    ALERT_EMAIL = os.environ.get('ALERT_EMAIL', 'security@cyberai.local')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')

    # CORS
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000']


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///cyber_ai_dev.db'   # SQLite fallback for easy dev setup
    )


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


# Config map
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    env = os.environ.get('FLASK_ENV', 'development')
    return config_map.get(env, DevelopmentConfig)
