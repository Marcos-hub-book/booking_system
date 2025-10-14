# migrate.py
from __init__ import create_app, db
from flask_migrate import upgrade

app = create_app()
with app.app_context():
    upgrade()