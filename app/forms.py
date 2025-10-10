from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TimeField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class AppointmentForm(FlaskForm):
    service = SelectField('Service', coerce=int, validators=[DataRequired()])
    professional = SelectField('Professional', coerce=int, validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()], format='%Y-%m-%d')
    time = TimeField('Time', validators=[DataRequired()], format='%H:%M')
    submit = SubmitField('Schedule Appointment')