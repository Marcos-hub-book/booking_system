from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TimeField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import Regexp

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Usuário (para o link)', validators=[DataRequired(), Length(min=3, max=64)])
    full_name = StringField('Nome completo', validators=[DataRequired(), Length(max=128)])
    company_name = StringField('Nome do salão/clínica', validators=[DataRequired(), Length(max=64)])
    phone = StringField('Telefone', validators=[Length(max=20)])
    cep = StringField('CEP', validators=[Length(max=10)])
    logradouro = StringField('Logradouro', validators=[Length(max=128)])
    numero = StringField('Número', validators=[Length(max=10)])
    cidade = StringField('Cidade', validators=[Length(max=64)])
    estado = StringField('Estado', validators=[Length(max=2)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    cpf = StringField('CPF', validators=[DataRequired(), Regexp(r'^\d{11}$', message='CPF deve conter 11 dígitos (somente números).')])
    password = PasswordField('Senha', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirmar senha', validators=[DataRequired(), EqualTo('password')])
    profile_photo = FileField('Foto de perfil', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'webp'], 'Somente imagens são permitidas.')])
    submit = SubmitField('Registrar')

class AppointmentForm(FlaskForm):
    service = SelectField('Serviço', coerce=int, validators=[DataRequired()])
    professional = SelectField('Profissional', coerce=int, validators=[DataRequired()])
    date = DateField('Data', validators=[DataRequired()], format='%Y-%m-%d')
    time = TimeField('Hora', validators=[DataRequired()], format='%H:%M')
    submit = SubmitField('Agendar Atendimento')