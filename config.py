from pathlib import Path

import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your_secret_key_here')
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL')
        or os.environ.get('SQLALCHEMY_DATABASE_URI')
        or os.environ.get('DB_URL')
        or 'postgresql://postgres:35268234@localhost:5432/booking_system'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Firebase configuration
    FIREBASE_CREDENTIALS_PATH = Path(__file__).parent / 'firebase_credentials.json'  # or set via env
    FIREBASE_PROJECT_ID = 'poraqui-notifications'  # set via env

    @staticmethod
    def init_app(app):
        pass