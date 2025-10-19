from . import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

customer_admin = db.Table('customer_admin',
    db.Column('customer_id', db.Integer, db.ForeignKey('customer.id')),
    db.Column('admin_id', db.Integer, db.ForeignKey('user.id'))
)

service_professional = db.Table('service_professional',
    db.Column('service_id', db.Integer, db.ForeignKey('service.id'), primary_key=True),
    db.Column('professional_id', db.Integer, db.ForeignKey('professional.id'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    company_name = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    role = db.Column(db.String(50), nullable=False)   # e.g., 'admin', 'professional'
    cep = db.Column(db.String(10))
    logradouro = db.Column(db.String(128))
    numero = db.Column(db.String(10))
    cidade = db.Column(db.String(64))
    estado = db.Column(db.String(2))
    profile_photo = db.Column(db.String(256))  # caminho da foto
    plan = db.Column(db.String(32), default="free")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @property
    def is_active(self):
        return True

    @property
    def is_authenticated(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

class Professional(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # cada profissional pertence a um admin
    admin = db.relationship('User', backref='professionals')

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    duration = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin = db.relationship('User', backref='services')
    professionals = db.relationship('Professional', secondary=service_professional, backref='services')

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    phone = db.Column(db.String(20), nullable=False, unique=False)
    admins = db.relationship('User', secondary=customer_admin, backref='customers')
    # Sugestão extra: email, data de cadastro, etc.

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=False)
    appointment_time = db.Column(db.DateTime, nullable=False)
    ativo = db.Column(db.Boolean, default=True)

    customer = db.relationship('Customer', backref='appointments')
    professional = db.relationship('Professional', backref='appointments')
    service = db.relationship('Service', backref='appointments')

class ProfessionalSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    professional_id = db.Column(db.Integer, db.ForeignKey('professional.id'), nullable=False)
    weekday = db.Column(db.Integer, nullable=False)  # 0=segunda, 6=domingo
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    break_start = db.Column(db.Time, nullable=True)
    break_end = db.Column(db.Time, nullable=True)

    professional = db.relationship('Professional', backref='schedules')

    
    
    