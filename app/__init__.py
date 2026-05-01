from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
import os
import json
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
    firebase_project_id = os.environ.get('FIREBASE_PROJECT_ID', 'poraqui-notifications')
    firebase_creds_json = os.environ.get('FIREBASE_CREDENTIALS_JSON')
    firebase_creds_path = os.environ.get('FIREBASE_CREDENTIALS_PATH', 'firebase_credentials.json')
    
    try:
        service_account_info = None
        
        # Primeira prioridade: variável de ambiente (usada no Railway)
        if firebase_creds_json:
            try:
                service_account_info = json.loads(firebase_creds_json)
                app.logger.info("Firebase inicializado com credenciais de FIREBASE_CREDENTIALS_JSON")
            except json.JSONDecodeError as e:
                app.logger.error(f"Erro ao parsear FIREBASE_CREDENTIALS_JSON: {e}")
        
        # Segunda prioridade: arquivo local (desenvolvimento)
        if not service_account_info and os.path.exists(firebase_creds_path):
            try:
                with open(firebase_creds_path, 'r') as f:
                    service_account_info = json.load(f)
                app.logger.info(f"Firebase inicializado com credenciais de {firebase_creds_path}")
            except Exception as e:
                app.logger.error(f"Erro ao ler {firebase_creds_path}: {e}")
        
        # Inicializar Firebase
        if service_account_info:
            cred = credentials.Certificate(service_account_info)
            firebase_admin.initialize_app(cred, options={'projectId': firebase_project_id})
        else:
            app.logger.warning("Nenhuma credencial Firebase encontrada. Tentando inicializar sem credenciais...")
            firebase_admin.initialize_app(options={'projectId': firebase_project_id})
    except Exception as e:
        app.logger.error(f"Erro ao inicializar Firebase: {e}")

    return app