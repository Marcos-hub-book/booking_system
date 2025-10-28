from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'chaveprojeto123')
    # Uploads
    upload_folder = os.path.join(app.root_path, 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_folder
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


    return app