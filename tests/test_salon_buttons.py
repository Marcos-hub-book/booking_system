import os

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

from app import create_app, db
from app.models import User, SalonButton


def test_salon_button_generates_whatsapp_and_location_links():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        admin = User(
            username='salon_test',
            full_name='Teste',
            company_name='Test Salon',
            password='hashed',
            email='admin@test.com',
            role='admin'
        )
        db.session.add(admin)
        db.session.flush()

        whatsapp = SalonButton(
            admin_id=admin.id,
            button_type='whatsapp',
            title='WhatsApp',
            description='Fale conosco',
            is_active=True,
            phone='5511999999999',
            sort_order=1,
        )
        location = SalonButton(
            admin_id=admin.id,
            button_type='location',
            title='Localização',
            description='Venha nos visitar',
            is_active=True,
            address='Av. Paulista, 1000 - São Paulo/SP',
            sort_order=2,
        )
        db.session.add_all([whatsapp, location])
        db.session.commit()

        assert whatsapp.build_url() == 'https://wa.me/5511999999999'
        assert location.build_url() == 'https://www.google.com/maps/search/?api=1&query=' + 'Av. Paulista, 1000 - São Paulo/SP'
