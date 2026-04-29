from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os
import cloudinary
import firebase_admin
from firebase_admin import credentials

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chaveprojeto123')
    # Uploads
    cloudinary.config(
        cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
        api_key=os.getenv("CLOUDINARY_API_KEY"),
        api_secret=os.getenv("CLOUDINARY_API_SECRET")
    )
    app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024  # 4MB
    
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        # Use a string pública do Railway para testes locais
        db_url = 'postgresql://postgres:WChEzjpJsfDanSsdClJDpHYZzVDmRKgg@hopper.proxy.rlwy.net:41618/railway'

    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    db.init_app(app)
    login_manager.init_app(app)
    migrate = Migrate(app, db)

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # Initialize Firebase
    firebase_creds_path = os.environ.get('FIREBASE_CREDENTIALS_PATH', 'firebase_credentials.json')
    if os.path.exists(firebase_creds_path):
        cred = credentials.Certificate(firebase_creds_path)
        firebase_admin.initialize_app(cred)
    else:
        # Fallback to environment variables or default project
        firebase_admin.initialize_app()

    return app