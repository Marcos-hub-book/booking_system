from app import create_app, db
from sqlalchemy import text

app = create_app()
with app.app_context():
    conn = db.engine
    try:
        conn.execute(text("ALTER TABLE location_schedule ADD COLUMN is_event boolean DEFAULT false;"))
        print('Added is_event column')
    except Exception as e:
        print('is_event add skipped:', e)
    try:
        conn.execute(text("ALTER TABLE location_schedule ADD COLUMN event_date date;"))
        print('Added event_date column')
    except Exception as e:
        print('event_date add skipped:', e)
