from datetime import datetime, timedelta

from app import create_app, db
from app.models import Appointment, Customer, Professional, Service, User, WhatsAppReminderQueue


def test_whatsapp_reminder_queue_can_be_created_for_valid_customer():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        admin = User(
            username='salon_test',
            full_name='Teste',
            company_name='Salon Test',
            password='hashed',
            email='admin@test.com',
            role='admin'
        )
        db.session.add(admin)
        db.session.flush()

        customer = Customer(
            name='Maria',
            birthdate='1990-01-01',
            phone='5511999999999',
            email='maria@test.com'
        )
        db.session.add(customer)
        db.session.flush()

        professional = Professional(name='Ana', admin_id=admin.id)
        service = Service(name='Corte', duration=60, price=80.0, admin_id=admin.id)
        db.session.add_all([professional, service])
        db.session.flush()

        appointment = Appointment(
            customer_id=customer.id,
            professional_id=professional.id,
            service_id=service.id,
            appointment_time=datetime.utcnow() + timedelta(days=2),
            ativo=True
        )
        db.session.add(appointment)
        db.session.flush()

        queue_item = WhatsAppReminderQueue(
            admin_id=admin.id,
            appointment_id=appointment.id,
            customer_id=customer.id,
            message_type='reminder_24h',
            status='queued',
            scheduled_for=datetime.utcnow() + timedelta(days=1),
            dedupe_key=f'{appointment.id}:reminder_24h'
        )
        db.session.add(queue_item)
        db.session.commit()

        assert queue_item.id is not None
        assert queue_item.status == 'queued'
        assert queue_item.customer_id == customer.id
