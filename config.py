from pathlib import Path

class Config:
    SECRET_KEY = 'your_secret_key_here'
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:35268234@localhost:5432/booking_system'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Firebase configuration
    FIREBASE_CREDENTIALS_PATH = Path(__file__).parent / 'firebase_credentials.json'  # or set via env
    FIREBASE_PROJECT_ID = 'poraqui-notifications'  # set via env

    @staticmethod
    def init_app(app):
        pass