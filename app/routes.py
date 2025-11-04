from flask import render_template, redirect, url_for, flash, request, Blueprint, abort, session, jsonify, g, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from . import db, login_manager
from .models import User, Professional, Service, Appointment, Customer, ProfessionalSchedule, Location, LocationSchedule, service_professional
from .models import Location
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, or_
from .forms import LoginForm, RegistrationForm, AppointmentForm
from sqlalchemy.orm import joinedload
from decimal import Decimal
import os
import jwt
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename
import requests

main = Blueprint('main', __name__)

# ==========================
# Plataforma Admin: login e painel de contas
# ==========================

def _platform_admin_authenticated():
    return session.get('platform_admin') is True

def _platform_admin_check_credentials(username, password):
    user_env = os.environ.get('PLATFORM_ADMIN_USER', 'platform')
    pass_env = os.environ.get('PLATFORM_ADMIN_PASS', 'platform123')
    return username == user_env and password == pass_env

@main.route('/platform/admin/login', methods=['GET', 'POST'])
def platform_admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if _platform_admin_check_credentials(username, password):
            session['platform_admin'] = True
            flash('Login de plataforma realizado com sucesso.', 'success')
            return redirect(url_for('main.platform_accounts'))
        flash('Credenciais inválidas.', 'danger')
        return render_template('platform_admin_login.html')
    return render_template('platform_admin_login.html')

@main.route('/platform/admin/logout', methods=['POST'])
def platform_admin_logout():
    session.pop('platform_admin', None)
    flash('Logout realizado.', 'success')
    return redirect(url_for('main.platform_admin_login'))

@main.route('/platform/accounts', methods=['GET'])
def platform_accounts():
    if not _platform_admin_authenticated():
        return redirect(url_for('main.platform_admin_login'))
    users = User.query.filter_by(role='admin').order_by(User.id.desc()).all()
    return render_template('platform_accounts.html', users=users)

# Ações de trial: iniciar, expirar, estender
def _platform_admin_required():
    if not _platform_admin_authenticated():
        abort(403)

@main.route('/platform/accounts/<int:user_id>/trial/start', methods=['POST'])
def platform_account_trial_start(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    if not user.trial_started_at:
        now = datetime.now()
        user.trial_started_at = now
        user.trial_ends_at = now + timedelta(days=30)
        user.trial_consumed = True
        user.subscription_status = 'trial'
        db.session.commit()
        flash('Trial iniciado para o usuário.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/trial/expire', methods=['POST'])
def platform_account_trial_expire(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    if user.trial_ends_at and user.subscription_status == 'trial':
        user.trial_ends_at = datetime.now()
        user.subscription_status = 'expired'
        db.session.commit()
        flash('Trial expirado para o usuário.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/trial/extend', methods=['POST'])
def platform_account_trial_extend(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    days = request.form.get('days', type=int)
    if user.trial_ends_at and days and days > 0:
        user.trial_ends_at += timedelta(days=days)
        db.session.commit()
        flash(f'Trial estendido em {days} dias.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/trial/reset', methods=['POST'])
def platform_account_trial_reset(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    # Zera os marcadores de trial deste usuário (não altera outros CPFs)
    user.trial_started_at = None
    user.trial_ends_at = None
    user.trial_consumed = False
    # Opcional: deixar status como None para não indicar trial ativo
    if (user.subscription_status or '').lower() == 'trial':
        user.subscription_status = None
    db.session.commit()
    flash('Trial do usuário foi resetado. Ele poderá iniciar novamente.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/trial/grant', methods=['POST'])
def platform_account_trial_grant(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    # Concede/força trial independentemente de flags anteriores
    days = request.form.get('days', type=int) or 30
    now = datetime.now()
    user.plan = user.plan or 'basic'
    user.subscription_status = 'trial'
    user.trial_started_at = now
    user.trial_ends_at = now + timedelta(days=days)
    user.trial_consumed = True
    db.session.commit()
    flash(f'Trial concedido por {days} dias.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/plan/update', methods=['POST'])
def platform_account_plan_update(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    plan = (request.form.get('plan') or '').lower()
    if plan not in ('free','basic','pro','advanced','avancado'):
        flash('Plano inválido.', 'danger')
        return redirect(url_for('main.platform_accounts'))
    user.plan = 'advanced' if plan in ('advanced','avancado') else plan
    db.session.commit()
    flash('Plano atualizado manualmente.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/activate/manual', methods=['POST'])
def platform_account_activate_manual(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    plan = (request.form.get('plan') or user.plan or 'basic').lower()
    days = request.form.get('days', type=int) or 30
    # Ativa assinatura manualmente
    user.plan = 'advanced' if plan in ('advanced','avancado') else plan
    user.subscription_status = 'active'
    user.subscription_provider = 'manual'
    user.subscription_id = f"manual-{user.id}-{int(datetime.utcnow().timestamp())}"
    user.current_period_end_at = datetime.now() + timedelta(days=days)
    db.session.commit()
    flash(f'Assinatura ativada manualmente ({user.plan.upper()}) por {days} dias.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/platform/accounts/<int:user_id>/status/set', methods=['POST'])
def platform_account_status_set(user_id):
    _platform_admin_required()
    user = User.query.get_or_404(user_id)
    status = (request.form.get('status') or '').lower().strip()
    allowed = {'active','canceled','cancelled','expired','trial','none','inactive'}
    if status not in allowed:
        flash('Status inválido.', 'danger')
        return redirect(url_for('main.platform_accounts'))
    if status in ('none','inactive',''):
        user.subscription_status = None
    elif status in ('canceled','cancelled'):
        user.subscription_status = 'canceled'
    else:
        user.subscription_status = status
    # Nota: não alteramos plan aqui; use a ação específica para isso
    db.session.commit()
    flash('Status de assinatura atualizado manualmente.', 'success')
    return redirect(url_for('main.platform_accounts'))

@main.route('/dashboard/add_event', endpoint='dashboard_add_event', methods=['POST'])
@login_required
def dashboard_add_event():
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    # Bloqueio simples como um Appointment sem service/customer
    professional_id = request.form.get('professional_id', type=int)
    date_str = request.form.get('data')
    time_str = request.form.get('hora')
    duracao = request.form.get('duracao', type=int)
    descricao = (request.form.get('descricao') or '').strip()
    if not (professional_id and date_str and time_str and duracao):
        flash('Preencha profissional, data, hora e duração.', 'danger')
        return redirect(url_for('main.dashboard'))
    prof = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first()
    if not prof:
        flash('Profissional inválido.', 'danger')
        return redirect(url_for('main.dashboard'))
    try:
        appt_time = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
    except Exception:
        flash('Data/hora inválida.', 'danger')
        return redirect(url_for('main.dashboard'))
    # Cria como Appointment ativo, sem service_id/customer_id
    bloqueio = Appointment(
        customer_id=None,
        professional_id=prof.id,
        service_id=None,
        location_id=None,
        appointment_time=appt_time,
        ativo=True,
        descricao=descricao or 'Bloqueio',
        duracao=duracao
    )
    db.session.add(bloqueio)
    db.session.commit()
    flash('Bloqueio criado com sucesso.', 'success')
    return redirect(url_for('main.dashboard', data=appt_time.strftime('%Y-%m-%d')))

# Rota real para adicionar agendamento via dashboard
@main.route('/dashboard/add_appointment', endpoint='dashboard_add_appointment', methods=['POST'])
@login_required
def dashboard_add_appointment():
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    # Coleta dados do formulário

    customer_name = request.form.get('customer_name')
    customer_phone = request.form.get('customer_phone')
    customer_email = request.form.get('customer_email')
    customer_birthdate = request.form.get('customer_birthdate')
    professional_id = request.form.get('professional_id', type=int)
    service_id = request.form.get('service_id', type=int)
    location_id = request.form.get('location_id', type=int)
    appointment_time = request.form.get('appointment_time')
    descricao = request.form.get('descricao')
    duracao = request.form.get('duracao', type=int)

    # Validação básica: apenas nome do cliente, profissional e horário são obrigatórios
    if not (customer_name and professional_id and appointment_time):
        flash('Preencha nome do cliente, profissional e horário.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Busca ou cria cliente (se telefone informado, busca por telefone; senão, busca por nome)
    customer = None
    if customer_phone:
        customer = Customer.query.filter_by(phone=customer_phone).first()
    if not customer:
        customer = Customer.query.filter_by(name=customer_name).first()
    if not customer:
        try:
            birthdate = datetime.strptime(customer_birthdate, '%Y-%m-%d').date() if customer_birthdate else datetime.now().date()
        except Exception:
            birthdate = datetime.now().date()
        customer = Customer(name=customer_name, phone=customer_phone, email=customer_email, birthdate=birthdate)
        customer.admins.append(current_user)
        db.session.add(customer)
        db.session.commit()
    elif current_user not in customer.admins:
        customer.admins.append(current_user)
        db.session.commit()

    # Cria agendamento
    try:
        appt_time = datetime.strptime(appointment_time, '%Y-%m-%d %H:%M')
    except Exception:
        flash('Data/hora do agendamento inválida.', 'danger')
        return redirect(url_for('main.dashboard'))

    appointment = Appointment(
        customer_id=customer.id,
        professional_id=professional_id,
        service_id=service_id,
        location_id=location_id,
        appointment_time=appt_time,
        ativo=True,
        descricao=descricao,
        duracao=duracao
    )
    db.session.add(appointment)
    db.session.commit()
    flash('Agendamento criado com sucesso!', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/dashboard/profile', endpoint='dashboard_profile', methods=['GET', 'POST'])
@login_required
def dashboard_profile():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        # Atualiza dados básicos
        company_name = (request.form.get('company_name') or '').strip()
        full_name = (request.form.get('full_name') or '').strip()
        phone = (request.form.get('phone') or '').strip()
        changed = False
        if company_name and company_name != current_user.company_name:
            current_user.company_name = company_name
            changed = True
        if full_name and full_name != current_user.full_name:
            current_user.full_name = full_name
            changed = True
        if phone and phone != current_user.phone:
            current_user.phone = phone
            changed = True
        # Upload de foto de perfil
        file = request.files.get('profile_photo')
        if file and file.filename:
            try:
                filename = secure_filename(file.filename)
                name, ext = os.path.splitext(filename)
                safe_name = f"user_{current_user.id}{ext.lower()}"
                upload_dir = current_app.config.get('UPLOAD_FOLDER')
                os.makedirs(upload_dir, exist_ok=True)
                save_path = os.path.join(upload_dir, safe_name)
                file.save(save_path)
                # Caminho relativo para static
                rel_path = os.path.relpath(save_path, os.path.join(current_app.root_path, 'static'))
                rel_path = rel_path.replace('\\', '/')
                current_user.profile_photo = rel_path
                changed = True
            except Exception as e:
                current_app.logger.exception('Falha ao salvar foto de perfil: %s', e)
                flash('Não foi possível salvar a foto de perfil.', 'danger')
        if changed:
            db.session.commit()
            flash('Perfil atualizado com sucesso.', 'success')
        else:
            flash('Nada para atualizar.', 'info')
        return redirect(url_for('main.dashboard_profile'))
    return render_template('dashboard_profile.html')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    return render_template('index.html')

# Simple alias route used by templates; redirect to dashboard for admins or login otherwise
@main.route('/schedule')
def schedule():
    if current_user.is_authenticated and getattr(current_user, 'role', None) == 'admin':
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))


# ==========================
# Utilities and middleware
# ==========================

def _get_jwt_secret():
    # Reuse Flask SECRET_KEY for signing customer JWTs unless CUSTOMER_JWT_SECRET is set
    return os.environ.get('CUSTOMER_JWT_SECRET', current_app.config.get('SECRET_KEY'))


def _create_customer_jwt(customer_id: int, name: str, admin_id: int, expires_days: int = 180):
    payload = {
        'sub': f'cust:{customer_id}',
        'cid': customer_id,
        'name': name,
        'aid': admin_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(days=expires_days)
    }
    token = jwt.encode(payload, _get_jwt_secret(), algorithm='HS256')
    return token


def _verify_customer_jwt(token: str):
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=['HS256'])
        return payload
    except Exception:
        return None


@main.before_app_request
def load_customer_from_cookie():
    # Bridge cookie-based customer auth to session for existing flow compatibility
    token = request.cookies.get('customer_jwt')
    if not token:
        g.customer_id = None
        g.customer_name = None
        return
    payload = _verify_customer_jwt(token)
    if not payload:
        g.customer_id = None
        g.customer_name = None
        return
    g.customer_id = payload.get('cid')
    g.customer_name = payload.get('name')
    session['customer_id'] = g.customer_id


@main.app_context_processor
def inject_customer_name():
    return {'customer_name': getattr(g, 'customer_name', None)}

@main.app_context_processor
def inject_profile_photo_helper():
    def profile_photo_url(path: str | None):
        if not path:
            return None
        p = str(path).replace('\\', '/').lstrip('/')
        if p.startswith('static/'):
            p = p[len('static/'):]
        return url_for('static', filename=p)
    return {'profile_photo_url': profile_photo_url}

# ==========================
# Billing/Plans helpers
# ==========================

def _get_cpf_key():
    """Return a valid Fernet key (base64 url-safe 32 bytes).
    Production-like: require CPF_ENCRYPTION_KEY to be set and valid; no fallback generation.
    """
    key = os.environ.get('CPF_ENCRYPTION_KEY')
    if not key:
        raise RuntimeError('CPF_ENCRYPTION_KEY não configurada no ambiente.')
    try:
        # validate
        Fernet(key.encode('utf-8'))
    except Exception as e:
        raise RuntimeError('CPF_ENCRYPTION_KEY inválida. Deve ser base64 url-safe de 32 bytes.') from e
    return key

def _encrypt_cpf(cpf_digits: str) -> str:
    f = Fernet(_get_cpf_key())
    return f.encrypt(cpf_digits.encode('utf-8')).decode('utf-8')

def _hash_cpf(cpf_digits: str) -> str:
    salt = os.environ.get('CPF_HASH_SALT', 'salt')
    return hashlib.sha256((cpf_digits + '|' + salt).encode('utf-8')).hexdigest()

def is_advanced(user: User) -> bool:
    return (user.plan or 'free').lower() in ('advanced','avancado')

# ==========================
# Assinatura: estado e restrições
# ==========================

def _is_account_in_good_standing(user: User) -> bool:
    """Conta apta para uso/link público: ativa ou em trial não expirado."""
    status = (user.subscription_status or '').lower()
    if status == 'active':
        return True
    if status == 'trial':
        if user.trial_ends_at:
            return user.trial_ends_at.date() >= datetime.today().date()
        return True
    return False

def _require_account_active_for_modifications():
    """Bloqueia ações de escrita quando conta está inativa/expirada."""
    if not _is_account_in_good_standing(current_user):
        flash('Sua conta está inativa ou com o plano expirado. Assine para continuar usando.', 'warning')
        return redirect(url_for('main.billing_expired'))
    return None

def _public_link_allowed(admin: User) -> bool:
    """Se o link público do salão deve responder."""
    return _is_account_in_good_standing(admin)

# ==========================
# Helpers de Plano (Free/Basic/Pro)
# ==========================

def _plan(user: User) -> str:
    return (user.plan or 'free').lower()

def is_free(user: User) -> bool:
    return _plan(user) == 'free'

def is_basic(user: User) -> bool:
    return _plan(user) == 'basic'

def is_pro(user: User) -> bool:
    return _plan(user) == 'pro'

def ensure_default_professional(admin: User) -> Professional:
    """No BASIC, garante um único profissional padrão com o nome da empresa."""
    prof = Professional.query.filter_by(admin_id=admin.id).first()
    if prof:
        return prof
    prof = Professional(name=admin.company_name, admin_id=admin.id)
    db.session.add(prof)
    db.session.commit()
    return prof

# ==========================
# Helpers: disponibilidade/validação de slots
# ==========================

def _is_slot_available(professional: Professional, start_dt: datetime, duration: int, admin_user: User, location_id: int | None = None) -> bool:
    weekday = start_dt.weekday()
    # Janelas do profissional
    schedules = ProfessionalSchedule.query.filter_by(professional_id=professional.id, weekday=weekday).all()
    # Janelas do Local (apenas BASIC)
    loc_schedules = []
    if is_basic(admin_user) and location_id:
        loc_schedules = LocationSchedule.query.filter_by(location_id=location_id, weekday=weekday).all()
    # Se profissional sem janela, usar do Local em BASIC
    if not schedules and loc_schedules:
        class S: pass
        schedules = []
        for lsch in loc_schedules:
            s = S()
            s.start_time = lsch.start_time
            s.end_time = lsch.end_time
            s.break_start = lsch.break_start
            s.break_end = lsch.break_end
            schedules.append(s)
    if not schedules:
        return False
    end_dt = start_dt + timedelta(minutes=duration)
    # Verifica se cai dentro de alguma janela e não em pausas
    inside_any = False
    for sch in schedules:
        s = datetime.combine(start_dt.date(), sch.start_time)
        e = datetime.combine(start_dt.date(), sch.end_time)
        if start_dt >= s and end_dt <= e:
            # pausa do profissional
            if sch.break_start and sch.break_end:
                bs = datetime.combine(start_dt.date(), sch.break_start)
                be = datetime.combine(start_dt.date(), sch.break_end)
                if start_dt < be and end_dt > bs:
                    continue
            inside_any = True
            break
    if not inside_any:
        return False
    # Se local ativo, validar também a janela/pausa do local
    if loc_schedules:
        inside_loc = False
        for lsch in loc_schedules:
            ls = datetime.combine(start_dt.date(), lsch.start_time)
            le = datetime.combine(start_dt.date(), lsch.end_time)
            if start_dt >= ls and end_dt <= le:
                if lsch.break_start and lsch.break_end:
                    lbs = datetime.combine(start_dt.date(), lsch.break_start)
                    lbe = datetime.combine(start_dt.date(), lsch.break_end)
                    if start_dt < lbe and end_dt > lbs:
                        continue
                inside_loc = True
                break
        if not inside_loc:
            return False
    # Conflitos com agendamentos/bloqueios existentes
    ags = Appointment.query.filter(
        Appointment.professional_id == professional.id,
        func.date(Appointment.appointment_time) == start_dt.date(),
        Appointment.ativo == True
    ).all()
    for ag in ags:
        if ag.service_id:
            d = Service.query.get(ag.service_id).duration
        else:
            d = ag.duracao or 0
        a_s = ag.appointment_time
        a_e = a_s + timedelta(minutes=d)
        if start_dt < a_e and end_dt > a_s:
            return False
    return True

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    print("Form valid:", form.validate_on_submit())
    print("Email:", form.email.data)
    print("Password:", form.password.data)
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            print("Usuário encontrado:", user.email)
            print("Senha correta?", user.check_password(form.password.data))
        else:
            print("Usuário não encontrado")
        if user and user.check_password(form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('main.dashboard'))
        flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)


# ==========================
# Customer phone login (password-based) pages and APIs
# ==========================

@main.route('/<salao_slug>/entrar', methods=['GET'])
def login_phone_screen(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    # If already authenticated as customer, go straight to options
    if getattr(g, 'customer_id', None):
        return redirect(url_for('main.cliente_opcoes', salao_slug=salao_slug))
    return render_template('cliente_login_phone.html', salao_slug=salao_slug, admin=admin)


def _normalize_phone(raw: str) -> str | None:
    if not raw:
        return None
    digits = ''.join(c for c in str(raw) if c.isdigit())
    # If comes with country code (e.g., 55 + 11 digits), keep last 11 for BR default
    if len(digits) > 11 and digits.startswith('55'):
        digits = digits[-11:]
    return digits if len(digits) == 11 else None


# Verifica se existe cliente por telefone (sem criar conta)
@main.route('/api/auth/check_phone', methods=['POST'])
def api_auth_check_phone():
    data = request.get_json(silent=True) or request.form or {}
    salao_slug = (data.get('salao_slug') or '').strip()
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404
    phone_raw = data.get('phone')
    phone = _normalize_phone(phone_raw)
    if not phone:
        return jsonify({'ok': False, 'error': 'invalid_phone'}), 400
    customer = Customer.query.filter_by(phone=phone).first()
    if not customer:
        return jsonify({'ok': True, 'exists': False})
    return jsonify({'ok': True, 'exists': True, 'name': customer.name})


# Login por telefone + senha (gera cookie JWT do cliente)
@main.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    salao_slug = (data.get('salao_slug') or '').strip()
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404
    phone = _normalize_phone(data.get('phone'))
    password = (data.get('password') or '').strip()
    if not (phone and password):
        return jsonify({'ok': False, 'error': 'missing_fields'}), 400
    customer = Customer.query.filter_by(phone=phone).first()
    if not customer or not customer.check_password(password):
        return jsonify({'ok': False, 'error': 'invalid_credentials'}), 401
    # Link with this salon/admin if not linked yet
    if admin not in customer.admins:
        customer.admins.append(admin)
        db.session.commit()
    jwt_token = _create_customer_jwt(customer.id, customer.name, admin.id)
    resp = jsonify({'ok': True})
    max_age = 60 * 60 * 24 * 180
    resp.set_cookie('customer_jwt', jwt_token, max_age=max_age, httponly=True, secure=False, samesite='Lax', path='/')
    return resp


# Registro de novo cliente (ou completa cadastro) e autentica
@main.route('/api/auth/register', methods=['POST'])
def api_auth_register():
    data = request.get_json(silent=True) or {}
    salao_slug = (data.get('salao_slug') or '').strip()
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404
    phone = _normalize_phone(data.get('phone'))
    first_name = (data.get('firstName') or '').strip()
    last_name = (data.get('lastName') or '').strip()
    email = (data.get('email') or '').strip() or None
    birthdate = (data.get('birthdate') or '').strip()
    password = (data.get('password') or '').strip()
    if not (phone and first_name and birthdate and password):
        return jsonify({'ok': False, 'error': 'missing_fields'}), 400
    full_name = f"{first_name} {last_name}".strip()
    try:
        bd = datetime.strptime(birthdate, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid_birthdate'}), 400
    customer = Customer.query.filter_by(phone=phone).first()
    if not customer:
        customer = Customer(name=full_name, birthdate=bd, phone=phone, email=email)
        customer.set_password(password)
        db.session.add(customer)
        db.session.commit()
    else:
        # Completa dados se necessário
        if not customer.password:
            customer.set_password(password)
        if email:
            customer.email = email
        if full_name and customer.name != full_name:
            customer.name = full_name
        if not customer.birthdate:
            customer.birthdate = bd
        db.session.commit()
    # Garante vínculo com o salão
    if admin not in customer.admins:
        customer.admins.append(admin)
        db.session.commit()
    jwt_token = _create_customer_jwt(customer.id, customer.name, admin.id)
    resp = jsonify({'ok': True})
    max_age = 60 * 60 * 24 * 180
    resp.set_cookie('customer_jwt', jwt_token, max_age=max_age, httponly=True, secure=False, samesite='Lax', path='/')
    return resp

@main.route('/logout-customer', methods=['POST'])
def logout_customer():
    resp = jsonify({'ok': True})
    resp.set_cookie('customer_jwt', '', expires=0, path='/')
    session.pop('customer_id', None)
    return resp

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # CPF validation (basic): ensure 11 digits and checksum
        raw_cpf = (form.cpf.data or '').strip()
        cpf_digits = ''.join([c for c in raw_cpf if c.isdigit()])
        if len(cpf_digits) != 11 or not _validate_cpf_checksum(cpf_digits):
            flash('CPF inválido. Use apenas números (11 dígitos).', 'danger')
            return render_template('register.html', form=form)
        try:
            enc = _encrypt_cpf(cpf_digits)
            hsh = _hash_cpf(cpf_digits)
        except Exception as e:
            current_app.logger.exception('Falha na criptografia/validação do CPF: %s', e)
            flash('Falha de configuração de segurança (CPF). Configure a variável CPF_ENCRYPTION_KEY corretamente e tente novamente.', 'danger')
            return render_template('register.html', form=form)
        new_user = User(
            username=form.username.data,
            full_name=form.full_name.data,
            company_name=form.company_name.data,
            phone=form.phone.data,
            email=form.email.data,
            cep=form.cep.data,
            logradouro=form.logradouro.data,
            numero=form.numero.data,
            cidade=form.cidade.data,
            estado=form.estado.data,
            role='admin',
            plan="free",
            cpf_encrypted=enc,
            cpf_hash=hsh
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()

        # Handle profile photo upload
        file = request.files.get('profile_photo')
        if file and file.filename:
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            # Use user id to avoid collisions
            safe_name = f"user_{new_user.id}{ext.lower()}"
            upload_dir = current_app.config.get('UPLOAD_FOLDER')
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, safe_name)
            file.save(save_path)
            # Store relative path under static for url_for
            rel_path = os.path.relpath(save_path, os.path.join(current_app.root_path, 'static'))
            rel_path = rel_path.replace('\\', '/')
            new_user.profile_photo = rel_path
            db.session.commit()
        flash('Conta criada com sucesso! Escolha um plano para começar.', 'success')
        # Autentica o novo admin imediatamente para que o fluxo de planos/trial use este usuário
        try:
            login_user(new_user)
        except Exception:
            current_app.logger.warning('Não foi possível autenticar automaticamente o novo usuário após cadastro.')
        return redirect(url_for('main.planos'))
    return render_template('register.html', form=form)

def _validate_cpf_checksum(cpf: str) -> bool:
    # Basic CPF checksum validation
    if cpf == cpf[0] * 11:
        return False
    def calc(digs):
        s = sum(int(d)*w for d, w in zip(digs, range(len(digs)+1, 1, -1)))
        r = (s * 10) % 11
        return 0 if r == 10 else r      # corrigido: else
    d1 = calc(cpf[:9])
    d2 = calc(cpf[:9] + str(d1))
    return cpf[-2:] == f"{d1}{d2}"

@main.route('/planos', methods=['GET'])
@login_required
def planos():
    if current_user.role != 'admin':
        abort(403)
    return render_template('planos.html')

@main.route('/planos/trial', methods=['POST'])
@login_required
def planos_trial():
    if current_user.role != 'admin':
        abort(403)
    plan_code = (request.form.get('plan') or '').lower()
    if plan_code not in ('basic','pro','advanced','avancado'):
        flash('Plano inválido.', 'danger')
        return redirect(url_for('main.planos'))
    # Trial eligibility: one per CPF (inclusive self) e não repetir para o mesmo usuário
    if not current_user.cpf_hash:
        flash('CPF ausente no cadastro. Atualize seu perfil.', 'danger')
        return redirect(url_for('main.planos'))
    if current_user.trial_consumed:
        flash('Você já utilizou um teste grátis anteriormente.', 'warning')
        return redirect(url_for('main.billing'))
    used = User.query.filter(User.cpf_hash == current_user.cpf_hash, User.trial_consumed == True, User.id != current_user.id).first()
    if used:
        flash('Você já utilizou um teste grátis anteriormente.', 'warning')
        return redirect(url_for('main.billing'))
    # Start trial
    now = datetime.now()
    current_user.plan = 'advanced' if plan_code in ('advanced','avancado') else plan_code
    current_user.subscription_status = 'trial'
    current_user.trial_started_at = now
    current_user.trial_ends_at = now + timedelta(days=30)
    current_user.trial_consumed = True
    db.session.commit()
    flash('Teste grátis iniciado! Aproveite 30 dias.', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/billing')
@login_required
def billing():
    if current_user.role != 'admin':
        abort(403)
    # Compute days left
    days_left = None
    if current_user.subscription_status == 'trial' and current_user.trial_ends_at:
        days_left = (current_user.trial_ends_at.date() - datetime.today().date()).days
    return render_template('billing.html', days_left=days_left)

@main.route('/billing/expired')
@login_required
def billing_expired():
    if current_user.role != 'admin':
        abort(403)
    return render_template('billing_expired.html')


@main.route('/billing/success')
@login_required
def billing_success():
    if current_user.role != 'admin':
        abort(403)
    preapproval_id = request.args.get('preapproval_id')
    # Se não veio na URL, tenta pegar do usuário
    if not preapproval_id and getattr(current_user, 'subscription_id', None):
        preapproval_id = current_user.subscription_id
    if preapproval_id:
        try:
            data = _mp_get_preapproval(preapproval_id)
            _apply_preapproval_to_user(current_user, data)
            db.session.commit()
            if current_user.subscription_status == 'active':
                flash('Assinatura ativada com sucesso!', 'success')
        except Exception as e:
            current_app.logger.exception("Erro ao confirmar assinatura: %s", e)
            flash('Falha ao confirmar assinatura.', 'danger')
    else:
        flash('ID da assinatura não encontrado.', 'warning')
    return render_template('billing_success.html')

# ==========================
# Webhook Mercado Pago
# ==========================
import hmac
import hashlib

@main.route('/webhook/mercadopago', methods=['POST'])
def webhook_mercadopago():
    # Opcional: validar assinatura/hmac se configurado no Mercado Pago
    # Exemplo: header 'X-Hub-Signature' ou 'X-Request-Signature'
    # signature = request.headers.get('X-Hub-Signature')
    # if signature:
    #     secret = os.environ.get('MP_WEBHOOK_SECRET', '')
    #     body = request.get_data()
    #     expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    #     if not hmac.compare_digest(signature, expected):
    #         return 'Invalid signature', 403


    # Log full payload for diagnostics
    try:
        data = request.get_json(silent=True) or {}
        current_app.logger.info(f"MercadoPago Webhook payload: {data}")
    except Exception as e:
        current_app.logger.error(f"Erro ao ler JSON do webhook: {e}")
        data = {}

    # Filtro: só processa eventos de preapproval
    event_type = data.get('type') or data.get('topic') or ''
    entity = data.get('entity') or ''
    # Mercado Pago pode enviar vários tipos de eventos, só queremos preapproval
    if event_type not in ['preapproval', 'subscription', 'subscription_preapproval'] and entity != 'preapproval':
        current_app.logger.info(f"Webhook ignorado: tipo de evento não é preapproval. type={event_type}, entity={entity}, payload={data}")
        return jsonify({'ok': False, 'ignored': True, 'reason': 'not preapproval event'}), 200

    # Try to extract preapproval_id from multiple possible fields
    preapproval_id = None
    if 'id' in data:
        preapproval_id = data['id']
    if not preapproval_id and isinstance(data.get('data'), dict):
        if 'id' in data['data']:
            preapproval_id = data['data']['id']
    if not preapproval_id and isinstance(data.get('resource'), dict):
        if 'id' in data['resource']:
            preapproval_id = data['resource']['id']
    # Às vezes 'resource' vem como string URL
    if not preapproval_id and isinstance(data.get('resource'), str):
        res = data.get('resource')
        if '/preapproval/' in res:
            try:
                preapproval_id = res.split('/preapproval/', 1)[1].split('?')[0].strip('/ ')
            except Exception:
                pass
    if not preapproval_id:
        preapproval_id = request.args.get('id')
    if not preapproval_id and 'subscription_id' in data:
        preapproval_id = data['subscription_id']
    # Alguns payloads trazem explicitamente 'preapproval_id' aninhado
    if not preapproval_id and isinstance(data.get('data'), dict):
        if 'preapproval_id' in data['data']:
            preapproval_id = data['data']['preapproval_id']

    if not preapproval_id:
        current_app.logger.warning(f"Webhook: preapproval_id not found. Payload: {data}, Args: {request.args}")
        return jsonify({'ok': False, 'error': 'preapproval_id not found'}), 400

    # Antes de chamar a API do MP, verifique se temos um usuário local com esse subscription_id.
    # Converte para string para evitar comparação varchar=bigint no banco
    preapproval_id = str(preapproval_id).strip()
    user = User.query.filter_by(subscription_id=preapproval_id).first()
    if not user:
        # Não temos esse ID localmente; provavelmente outro tipo de assinatura/evento.
        current_app.logger.info(f"Webhook ignorado: nenhum usuário local com subscription_id={preapproval_id}. Evitando chamada ao MP.")
        return jsonify({'ok': True, 'ignored': True, 'reason': 'unknown subscription_id'}), 200

    # Busca preapproval no MP e atualiza usuário
    try:
        current_app.logger.info(f"Webhook: preapproval_id recebido: {preapproval_id}")
        preapproval = _mp_get_preapproval(preapproval_id)
        current_app.logger.info(f"Webhook: preapproval data: {preapproval}")
        _apply_preapproval_to_user(user, preapproval)
        db.session.commit()
        current_app.logger.info(f"Webhook: assinatura atualizada para user_id={user.id}, status={user.subscription_status}")
        return jsonify({'ok': True, 'user_id': user.id, 'status': user.subscription_status})
    except Exception as e:
        current_app.logger.error(f"Webhook: erro ao processar preapproval_id={preapproval_id}. Exception: {e}")
        current_app.logger.exception('Erro no webhook Mercado Pago: %s', e)
        return jsonify({'ok': False, 'error': str(e), 'preapproval_id': preapproval_id}), 500

@main.route('/billing/cancel', methods=['POST'])
@login_required
def billing_cancel():
    if current_user.role != 'admin':
        abort(403)
    try:
        if (current_user.subscription_provider == 'mercadopago') and current_user.subscription_id:
            try:
                _mp_cancel_preapproval(current_user.subscription_id)
            except Exception as e:
                current_app.logger.exception('Erro ao cancelar no Mercado Pago: %s', e)
                flash('Não foi possível cancelar no Mercado Pago agora. Tente novamente em instantes.', 'warning')
                return redirect(url_for('main.billing'))
        # Atualiza estado local
        current_user.subscription_status = 'canceled'
        current_user.canceled_at = datetime.now()
        current_user.current_period_end_at = None
        current_user.plan = 'free'
        db.session.commit()
        flash('Assinatura cancelada com sucesso.', 'success')
    except Exception as e:
        current_app.logger.exception('Falha ao cancelar assinatura localmente: %s', e)
        flash('Falha ao cancelar assinatura.', 'danger')
    return redirect(url_for('main.billing'))

@main.route('/account/close', methods=['GET'])
@login_required
def account_close():
    if current_user.role != 'admin':
        abort(403)
    return render_template('account_close.html')

@main.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    if current_user.role != 'admin':
        abort(403)
    # Minimal agenda dashboard context to avoid errors if data is missing
    try:
        date_str = request.args.get('data')
        data = datetime.strptime(date_str, '%Y-%m-%d').date() if date_str else datetime.today().date()
    except Exception:
        data = datetime.today().date()
    professional_id = request.args.get('professional_id', type=int)
    status = request.args.get('status', default='ativos')
    profissionais = Professional.query.filter_by(admin_id=current_user.id).all()
    servicos = Service.query.filter_by(admin_id=current_user.id).all()
    locations = Location.query.filter_by(admin_id=current_user.id).all()
    # Busca agendamentos do banco de dados
    query = Appointment.query.options(joinedload(Appointment.professional), joinedload(Appointment.service), joinedload(Appointment.customer), joinedload(Appointment.location)).join(Professional).filter(Professional.admin_id == current_user.id)
    query = query.filter(func.date(Appointment.appointment_time) == data)
    if professional_id:
        query = query.filter(Appointment.professional_id == professional_id)
    if status == 'ativos':
        query = query.filter(Appointment.ativo == True)
    elif status == 'cancelados':
        query = query.filter(Appointment.ativo == False)
    agendamentos = query.order_by(Appointment.appointment_time.asc()).all()
    # Adiciona timedelta ao contexto para o template
    return render_template('dashboard_agenda.html', data=data, professional_id=professional_id,
                           status=status, profissionais=profissionais, servicos=servicos,
                           locations=locations, agendamentos=agendamentos, timedelta=timedelta)

# Rota para cancelar agendamento pelo dashboard (mantida após dashboard)
@main.route('/dashboard/cancelar_agendamento/<int:agendamento_id>', methods=['POST'])
@login_required
def dashboard_cancelar_agendamento(agendamento_id):
    agendamento = Appointment.query.join(Professional).filter(Appointment.id == agendamento_id, Professional.admin_id == current_user.id).first_or_404()
    agendamento.ativo = False
    db.session.commit()
    flash('Agendamento cancelado com sucesso.', 'success')
    # Redireciona para o dashboard na mesma data
    date_str = agendamento.appointment_time.strftime('%Y-%m-%d')
    return redirect(url_for('main.dashboard', data=date_str))

# Rota para retornar horários disponíveis (slots) para agendamento
@main.route('/dashboard/available_times', methods=['GET'])
@login_required
def dashboard_available_times():
    if current_user.role != 'admin':
        abort(403)
    professional_id = request.args.get('professional_id', type=int)
    service_id = request.args.get('service_id', type=int)
    date_str = request.args.get('date')
    location_id = request.args.get('location_id', type=int)
    if not (professional_id and service_id and date_str):
        return jsonify({'ok': False, 'error': 'missing_parameters'}), 400
    professional = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first()
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first()
    if not professional or not service:
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid_date'}), 400
    duration = service.duration
    # Gera slots de 15 em 15 minutos entre o horário de início e fim do profissional/local
    weekday = date.weekday()
    # Busca janelas do profissional
    schedules = ProfessionalSchedule.query.filter_by(professional_id=professional.id, weekday=weekday).all()
    # Se plano BASIC e location_id, busca janelas do local
    loc_schedules = []
    if is_basic(current_user) and location_id:
        loc_schedules = LocationSchedule.query.filter_by(location_id=location_id, weekday=weekday).all()
    # Se profissional sem janela, usar do Local em BASIC
    if not schedules and loc_schedules:
        class S: pass
        schedules = []
        for lsch in loc_schedules:
            s = S()
            s.start_time = lsch.start_time
            s.end_time = lsch.end_time
            s.break_start = lsch.break_start
            s.break_end = lsch.break_end
            schedules.append(s)
    slots = []
    for sch in schedules:
        start_dt = datetime.combine(date, sch.start_time)
        end_dt = datetime.combine(date, sch.end_time)
        current = start_dt
        while current + timedelta(minutes=duration) <= end_dt:
            # Verifica se está em pausa
            in_break = False
            if sch.break_start and sch.break_end:
                bs = datetime.combine(date, sch.break_start)
                be = datetime.combine(date, sch.break_end)
                if current < be and (current + timedelta(minutes=duration)) > bs:
                    in_break = True
            # Verifica se slot está disponível
            if not in_break and _is_slot_available(professional, current, duration, current_user, location_id):
                slots.append(current.strftime('%H:%M'))
            current += timedelta(minutes=15)
    return jsonify({'ok': True, 'slots': slots})


@main.route('/dashboard/services_for', methods=['GET'])
@login_required
def dashboard_services_for():
    """Return services filtered by current plan and selections.
    - BASIC: filter by location_id if provided
    - PRO/ADVANCED: filter by professional_id if provided
    """
    if current_user.role != 'admin':
        abort(403)
    professional_id = request.args.get('professional_id', type=int)
    location_id = request.args.get('location_id', type=int)
    q = Service.query.filter_by(admin_id=current_user.id)
    if is_basic(current_user):
        if location_id:
            q = q.join(Service.locations).filter(Location.id == location_id)
    else:
        if professional_id:
            q = q.join(service_professional, Service.id == service_professional.c.service_id) \
                 .filter(service_professional.c.professional_id == professional_id)
    services = q.order_by(Service.name.asc()).all()
    return jsonify({'ok': True, 'services': [{'id': s.id, 'name': s.name, 'duration': s.duration} for s in services]})

@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'success')
    return redirect(url_for('main.login'))


@main.route('/api/customers/search', methods=['GET'])
@login_required
def api_customers_search():
    if current_user.role != 'admin':
        abort(403)
    q = (request.args.get('q') or '').strip()
    if not q:
        return jsonify({'ok': True, 'results': []})
    # Busca clientes vinculados a este admin por nome ou telefone
    results = Customer.query.join(Customer.admins) \
        .filter(User.id == current_user.id) \
        .filter(or_(Customer.name.ilike(f'%{q}%'), Customer.phone.ilike(f'%{q}%'))) \
        .order_by(Customer.name.asc()).limit(8).all()
    return jsonify({'ok': True, 'results': [{'id': c.id, 'name': c.name, 'phone': c.phone} for c in results]})

@main.route('/professionals', endpoint='professionals_list', methods=['GET'])
@login_required
def professionals_list():
    if current_user.role != 'admin':
        abort(403)
    pros = Professional.query.filter_by(admin_id=current_user.id).all()
    return render_template('professionals_list.html', professionals=pros, back_url=url_for('main.dashboard'))

@main.route('/services', endpoint='services_list', methods=['GET'])
@login_required
def services_list():
    if current_user.role != 'admin':
        abort(403)
    services = Service.query.options(joinedload(Service.professionals), joinedload(Service.locations)).filter_by(admin_id=current_user.id).all()
    return render_template('services_list.html', services=services)

# Rota para editar serviço
@main.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    pros = Professional.query.filter_by(admin_id=current_user.id).all()
    locs = Location.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        duration = request.form.get('duration', type=int)
        price = request.form.get('price', type=float)
        if not (name and duration and price is not None):
            flash('Preencha nome, duração e preço.', 'danger')
            return render_template('edit_service.html', service=service, professionals=pros, locations=locs)
        service.name = name
        service.duration = duration
        service.price = price
        # Atualizar profissionais
        pro_ids = request.form.getlist('professional_ids')
        service.professionals = Professional.query.filter(Professional.id.in_(pro_ids), Professional.admin_id==current_user.id).all() if pro_ids else []
        # Atualizar locais
        loc_ids = request.form.getlist('location_ids')
        service.locations = Location.query.filter(Location.id.in_(loc_ids), Location.admin_id==current_user.id).all() if loc_ids else []
        db.session.commit()
        flash('Serviço atualizado com sucesso.', 'success')
        return redirect(url_for('main.services_list'))
    return render_template('edit_service.html', service=service, professionals=pros, locations=locs)

# Rota para confirmar exclusão de serviço
@main.route('/services/<int:service_id>/delete', methods=['GET', 'POST'])
@login_required
def confirm_delete_service(service_id):
    if current_user.role != 'admin':
        abort(403)
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    if request.method == 'POST':
        db.session.delete(service)
        db.session.commit()
        flash('Serviço excluído com sucesso.', 'success')
        return redirect(url_for('main.services_list'))
    return render_template('confirm_delete_service.html', service=service)


@main.route('/locations', endpoint='locations_list', methods=['GET'])
@login_required
def locations_list():
    if current_user.role != 'admin':
        abort(403)
    locs = Location.query.options(joinedload(Location.schedules)).filter_by(admin_id=current_user.id).all()
    return render_template('locations_list.html', locations=locs)

# Nova rota para editar local
@main.route('/locations/<int:location_id>/edit', endpoint='edit_location', methods=['GET', 'POST'])
@login_required
def edit_location(location_id):
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    loc = Location.query.filter_by(id=location_id, admin_id=current_user.id).first_or_404()
    # Adiciona os horários do local para o template
    horarios = {h.weekday: h for h in LocationSchedule.query.filter_by(location_id=loc.id).all()}
    # Lista de dias da semana para o template
    dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        if name:
            loc.name = name
            db.session.commit()
            flash('Local atualizado com sucesso.', 'success')
            return redirect(url_for('main.locations_list'))
        flash('Nome do local é obrigatório.', 'danger')
    return render_template('edit_location.html', location=loc, horarios=horarios, dias=dias)

@main.route('/professionals/add', endpoint='add_professional', methods=['GET','POST'])
@login_required
def add_professional():
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        if not name:
            flash('Nome do profissional é obrigatório.', 'danger')
            return redirect(url_for('main.add_professional'))
        # Limites por plano: PRO=2, ADVANCED=5
        limit = None
        if is_pro(current_user):
            limit = 2
        elif is_advanced(current_user):
            limit = 5
        if limit is not None:
            count = Professional.query.filter_by(admin_id=current_user.id).count()
            if count >= limit:
                flash(f'Limite de profissionais do seu plano atingido ({limit}). Atualize seu plano para adicionar mais.', 'warning')
                return redirect(url_for('main.professionals_list'))
        # Cria profissional
        prof = Professional(name=name, admin_id=current_user.id)
        db.session.add(prof)
        db.session.flush()  # garante prof.id para criar horários

        # Salva dias/horários de trabalho se enviados
        try:
            workdays = set(int(x) for x in request.form.getlist('workdays'))
        except Exception:
            workdays = set()
        for i in workdays:
            start_val = (request.form.get(f'start_{i}') or '').strip()
            end_val = (request.form.get(f'end_{i}') or '').strip()
            bstart_val = (request.form.get(f'break_start_{i}') or '').strip()
            bend_val = (request.form.get(f'break_end_{i}') or '').strip()
            if not (start_val and end_val):
                # Ignora dias marcados sem início/fim
                continue
            try:
                st = datetime.strptime(start_val, '%H:%M').time()
                en = datetime.strptime(end_val, '%H:%M').time()
                bs = datetime.strptime(bstart_val, '%H:%M').time() if bstart_val else None
                be = datetime.strptime(bend_val, '%H:%M').time() if bend_val else None
            except Exception:
                # Se algum horário for inválido, pula silenciosamente
                continue
            db.session.add(ProfessionalSchedule(professional_id=prof.id, weekday=i, start_time=st, end_time=en, break_start=bs, break_end=be))

        db.session.commit()
        flash('Profissional adicionado.', 'success')
        return redirect(url_for('main.professionals_list'))
    return render_template('add_professional.html', back_url=url_for('main.professionals_list'))


@main.route('/services/add', endpoint='add_service', methods=['GET','POST'])
@login_required
def add_service():
    if current_user.role != 'admin':
        abort(403)
    redir = _require_account_active_for_modifications()
    if redir:
        return redir
    pros = Professional.query.filter_by(admin_id=current_user.id).all()
    locs = Location.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        duration = request.form.get('duration', type=int)
        price = request.form.get('price', type=float)
        if not (name and duration and price is not None):
            flash('Preencha nome, duração e preço.', 'danger')
            return render_template('add_service.html', professionals=pros, locations=locs)
        service = Service(name=name, duration=duration, price=price, admin_id=current_user.id)
        # Profissionais
        pro_ids = request.form.getlist('professional_ids')
        service.professionals = Professional.query.filter(Professional.id.in_(pro_ids), Professional.admin_id==current_user.id).all() if pro_ids else []
        # Locais
        loc_ids = request.form.getlist('location_ids')
        service.locations = Location.query.filter(Location.id.in_(loc_ids), Location.admin_id==current_user.id).all() if loc_ids else []
        db.session.add(service)
        db.session.commit()
        flash('Serviço adicionado com sucesso.', 'success')
        return redirect(url_for('main.services_list'))
    return render_template('add_service.html', professionals=pros, locations=locs)

PLAN_PRICES = {
    'basic': Decimal('19.90'),
    'pro': Decimal('29.90'),
    'advanced': Decimal('49.90'),
}

def _mp_access_token() -> str:
    token = os.getenv('MERCADO_PAGO_ACCESS_TOKEN', '').strip()
    if not token:
        raise RuntimeError('MERCADO_PAGO_ACCESS_TOKEN não configurado')
    return token

def _mp_payer_email(user) -> str:
    token = os.getenv('MERCADO_PAGO_ACCESS_TOKEN', '').strip()
    test_payer = os.getenv('MERCADO_PAGO_TEST_PAYER', '').strip()
    # Se estamos em sandbox (token de teste) e foi informado um comprador de teste, usar ele
    if token.startswith('TEST-') and test_payer:
        return test_payer
    return user.email

def _mp_create_preapproval(user, plan_key: str, amount: Decimal):
    import requests
    payload = {
        "reason": f"Assinatura Plano {plan_key.capitalize()}",
        "auto_recurring": {
            "frequency": 1,
            "frequency_type": "months",
            "transaction_amount": float(amount),
            "currency_id": "BRL"
        },
        # prefixo do blueprint 'main'
        "back_url": url_for('main.billing_success', _external=True),
        "payer_email": _mp_payer_email(user),
    }
    headers = {
        'Authorization': f'Bearer {_mp_access_token()}',
        'Content-Type': 'application/json',
        'X-Idempotency-Key': f"preapproval-{user.id}-{plan_key}-{datetime.utcnow().timestamp()}",
    }
    resp = requests.post('https://api.mercadopago.com/preapproval', json=payload, headers=headers, timeout=20)
    if resp.status_code >= 300:
        current_app.logger.error(f"Falha ao criar preapproval no MP: {resp.status_code} {resp.text}")
        raise RuntimeError(f"MP preapproval error: {resp.status_code} {resp.text}")
    return resp.json()

def _mp_get_preapproval(preapproval_id: str) -> dict:
    """Fetch preapproval by id from Mercado Pago."""
    headers = {
        'Authorization': f'Bearer {_mp_access_token()}',
        'Content-Type': 'application/json',
    }
    url = f'https://api.mercadopago.com/preapproval/{preapproval_id}'
    resp = requests.get(url, headers=headers, timeout=20)
    if resp.status_code >= 300:
        current_app.logger.error(f"Falha ao obter preapproval no MP: {resp.status_code} {resp.text}")
        raise RuntimeError(f"MP get preapproval error: {resp.status_code} {resp.text}")
    return resp.json()

def _apply_preapproval_to_user(user: User, preapproval_data: dict) -> None:
    """Update local user subscription fields based on Mercado Pago preapproval payload."""
    status = (preapproval_data.get('status') or '').lower()
    auto_rec = preapproval_data.get('auto_recurring') or {}
    next_payment_date = auto_rec.get('next_payment_date')
    # Map MP status to our status
    # IMPORTANT: Do not downgrade or set to 'pending' during checkout; only update on effective states
    if status in ('authorized', 'active', 'approved'):
        user.subscription_status = 'active'
        # Update user's plan based on preapproval reason if available (ensures plan changes only after activation)
        reason = (preapproval_data.get('reason') or '').lower()
        # Expected: "Assinatura Plano Basic/Pro/Advanced"
        if 'advanced' in reason or 'avançado' in reason or 'avancado' in reason:
            user.plan = 'advanced'
        elif 'pro' in reason:
            user.plan = 'pro'
        elif 'basic' in reason or 'básico' in reason or 'basico' in reason:
            user.plan = 'basic'
        # else: keep current plan (e.g., trial) if reason not parseable
    elif status in ('paused', 'cancelled', 'canceled'):
        user.subscription_status = 'canceled'
        # Optional: keep current plan until cancel flow sets to free; avoid surprising downgrades here
    elif status in ('expired',):
        user.subscription_status = 'expired'
        # Do not change plan automatically here
    else:
        # Unknown/transient status (e.g., pending): do not alter current subscription_status
        pass
    # Persist provider/id just in case
    user.subscription_provider = 'mercadopago'
    if preapproval_data.get('id'):
        user.subscription_id = preapproval_data['id']
    # Parse next period end if available
    if next_payment_date:
        try:
            # Handle ISO8601 with Z
            iso = str(next_payment_date).replace('Z', '+00:00')
            dt = datetime.fromisoformat(iso)
            # store naive datetime in local time if needed
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            user.current_period_end_at = dt
        except Exception:
            current_app.logger.warning('Não foi possível interpretar next_payment_date: %s', next_payment_date)

def _mp_cancel_preapproval(preapproval_id: str) -> dict:
    """Cancel a preapproval (subscription) on Mercado Pago."""
    headers = {
        'Authorization': f'Bearer {_mp_access_token()}',
        'Content-Type': 'application/json',
    }
    url = f'https://api.mercadopago.com/preapproval/{preapproval_id}'
    payload = {"status": "cancelled"}
    resp = requests.put(url, json=payload, headers=headers, timeout=20)
    if resp.status_code >= 300:
        current_app.logger.error(f"Falha ao cancelar preapproval no MP: {resp.status_code} {resp.text}")
        raise RuntimeError(f"MP cancel preapproval error: {resp.status_code} {resp.text}")
    return resp.json()

# Trocar @app.post por decorator do blueprint:
@main.route('/subscriptions/create', methods=['POST'])
@login_required
def subscriptions_create():
    try:
        plan_key = request.form.get('plan') or (current_user.plan if current_user.plan in PLAN_PRICES else 'basic')
        if plan_key not in PLAN_PRICES:
            flash('Plano inválido.', 'error')
            return redirect(url_for('main.billing'))
        amount = PLAN_PRICES[plan_key]

        preapproval = _mp_create_preapproval(current_user, plan_key, amount)
        init_point = preapproval.get('init_point') or preapproval.get('sandbox_init_point')
        if not init_point:
            flash('Falha ao iniciar assinatura no Mercado Pago. Tente novamente.', 'error')
            return redirect(url_for('main.billing'))

        current_user.subscription_provider = 'mercadopago'
        current_user.subscription_id = preapproval.get('id')
        # Do NOT change subscription_status/plan here; keep access as-is until confirmation
        db.session.commit()

        return redirect(init_point)
    except RuntimeError as e:
        msg = str(e)
        if 'Cannot pay an amount lower than' in msg:
            msg = 'O valor da assinatura deve be de pelo menos R$ 0,50. Já estamos usando os preços reais do plano.'
        elif 'MERCADO_PAGO_ACCESS_TOKEN' in msg:
            msg = 'Token do Mercado Pago não configurado no servidor.'
        elif 'test' in msg.lower() and 'payer' in msg.lower():
            msg = 'No sandbox, use um comprador de teste (MERCADO_PAGO_TEST_PAYER) diferente do vendedor.'
        current_app.logger.error(f'Falha ao iniciar assinatura: {msg}')
        flash(f'Falha ao iniciar assinatura no Mercado Pago. {msg}', 'danger')
        return redirect(url_for('main.billing'))

@main.route('/dbtest')
def dbtest():
    try:
        count = db.session.query(User).count()
        return f"Conexão OK! Usuários cadastrados: {count}"
    except Exception as e:
        return f"Erro na conexão: {e}", 500


# ==========================
# Admin: profissionais (editar/excluir) e locais (adicionar)
# ==========================

@main.route('/professionals/<int:professional_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_professional(professional_id):
    if current_user.role != 'admin':
        abort(403)
    prof = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first_or_404()
    dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb', 'Dom']
    # Mapa weekday -> schedule
    horarios = {h.weekday: h for h in ProfessionalSchedule.query.filter_by(professional_id=prof.id).all()}
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        if not name:
            flash('Nome é obrigatório.', 'danger')
            return render_template('edit_professional.html', professional=prof, dias=dias, horarios=horarios)
        prof.name = name
        # Atualiza horários
        workdays = set(int(x) for x in request.form.getlist('workdays'))
        # Remove dias que não estão selecionados
        for wd, sch in list(horarios.items()):
            if wd not in workdays:
                db.session.delete(sch)
                horarios.pop(wd, None)
        # Cria/atualiza selecionados
        for i in workdays:
            start_val = (request.form.get(f'start_{i}') or '').strip()
            end_val = (request.form.get(f'end_{i}') or '').strip()
            bstart_val = (request.form.get(f'break_start_{i}') or '').strip()
            bend_val = (request.form.get(f'break_end_{i}') or '').strip()
            if not (start_val and end_val):
                # Se dia marcado sem horas, ignora
                continue
            try:
                st = datetime.strptime(start_val, '%H:%M').time()
                en = datetime.strptime(end_val, '%H:%M').time()
                bs = datetime.strptime(bstart_val, '%H:%M').time() if bstart_val else None
                be = datetime.strptime(bend_val, '%H:%M').time() if bend_val else None
            except Exception:
                continue
            sch = horarios.get(i)
            if not sch:
                sch = ProfessionalSchedule(professional_id=prof.id, weekday=i, start_time=st, end_time=en, break_start=bs, break_end=be)
                db.session.add(sch)
                horarios[i] = sch
            else:
                sch.start_time = st
                sch.end_time = en
                sch.break_start = bs
                sch.break_end = be
        db.session.commit()
        flash('Profissional atualizado com sucesso.', 'success')
        return redirect(url_for('main.professionals_list'))
    return render_template('edit_professional.html', professional=prof, dias=dias, horarios=horarios)


@main.route('/professionals/<int:professional_id>/delete', methods=['GET', 'POST'])
@login_required
def confirm_delete_professional(professional_id):
    if current_user.role != 'admin':
        abort(403)
    prof = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first_or_404()
    if request.method == 'POST':
        # Exclui agendamentos e horários ligados a este profissional
        Appointment.query.filter_by(professional_id=prof.id).delete(synchronize_session=False)
        ProfessionalSchedule.query.filter_by(professional_id=prof.id).delete(synchronize_session=False)
        db.session.delete(prof)
        db.session.commit()
        flash('Profissional excluído com sucesso.', 'success')
        return redirect(url_for('main.professionals_list'))
    return render_template('confirm_delete_professional.html', professional=prof)


@main.route('/locations/add', methods=['GET', 'POST'])
@login_required
def add_location():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        if not name:
            flash('Nome do local é obrigatório.', 'danger')
            return render_template('add_location.html')
        loc = Location(name=name, admin_id=current_user.id)
        db.session.add(loc)
        db.session.flush()  # obtém loc.id antes de commit
        workdays = set(int(x) for x in request.form.getlist('workdays'))
        for i in workdays:
            start_val = (request.form.get(f'start_{i}') or '').strip()
            end_val = (request.form.get(f'end_{i}') or '').strip()
            bstart_val = (request.form.get(f'break_start_{i}') or '').strip()
            bend_val = (request.form.get(f'break_end_{i}') or '').strip()
            if not (start_val and end_val):
                continue
            try:
                st = datetime.strptime(start_val, '%H:%M').time()
                en = datetime.strptime(end_val, '%H:%M').time()
                bs = datetime.strptime(bstart_val, '%H:%M').time() if bstart_val else None
                be = datetime.strptime(bend_val, '%H:%M').time() if bend_val else None
            except Exception:
                continue
            db.session.add(LocationSchedule(location_id=loc.id, weekday=i, start_time=st, end_time=en, break_start=bs, break_end=be))
        db.session.commit()
        flash('Local adicionado com sucesso.', 'success')
        return redirect(url_for('main.locations_list'))
    return render_template('add_location.html')


# ==========================
# Fluxo do cliente (páginas do salão)
# ==========================

def _require_customer_auth(salao_slug):
    if not getattr(g, 'customer_id', None):
        return redirect(url_for('main.login_phone_screen', salao_slug=salao_slug))
    return None


@main.route('/<salao_slug>')
def salao_home(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    return render_template('salao_home.html', admin=admin)


@main.route('/<salao_slug>/opcoes')
def cliente_opcoes(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    # exige autenticação de cliente
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    has_locations = Location.query.filter_by(admin_id=admin.id).count() > 0
    return render_template('cliente_opcoes.html', salao_slug=salao_slug, has_locations=has_locations)


@main.route('/<salao_slug>/local', methods=['GET', 'POST'])
def salao_local(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    if request.method == 'POST':
        location_id = request.form.get('location_id', type=int)
        if location_id:
            return redirect(url_for('main.salao_servico', salao_slug=salao_slug, location_id=location_id))
    locs = Location.query.filter_by(admin_id=admin.id).all()
    return render_template('cliente_local.html', locations=locs, salao_slug=salao_slug, back_url=url_for('main.cliente_opcoes', salao_slug=salao_slug))


@main.route('/<salao_slug>/servico', methods=['GET', 'POST'])
def salao_servico(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    location_id = request.args.get('location_id', type=int)
    q = Service.query.filter_by(admin_id=admin.id)
    if is_basic(admin) and location_id:
        q = q.join(Service.locations).filter(Location.id == location_id)
    services = q.order_by(Service.name.asc()).all()
    if request.method == 'POST':
        service_id = request.form.get('service_id', type=int)
        if service_id:
            return redirect(url_for('main.cliente_profissional', salao_slug=salao_slug, service_id=service_id, location_id=location_id))
    back_url = url_for('main.salao_local', salao_slug=salao_slug) if Location.query.filter_by(admin_id=admin.id).count() > 0 else url_for('main.cliente_opcoes', salao_slug=salao_slug)
    return render_template('cliente_servico.html', services=services, salao_slug=salao_slug, back_url=back_url)


@main.route('/<salao_slug>/profissional', methods=['GET', 'POST'], endpoint='cliente_profissional')
def cliente_profissional_route(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    service_id = request.args.get('service_id', type=int)
    location_id = request.args.get('location_id', type=int)
    if not service_id:
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug, location_id=location_id))
    # profissionais associados ao serviço
    pros = Professional.query.join(service_professional, Professional.id == service_professional.c.professional_id)
    pros = pros.filter(service_professional.c.service_id == service_id, Professional.admin_id == admin.id).all()
    # fallback: se nenhum associado, lista todos do admin
    if not pros:
        pros = Professional.query.filter_by(admin_id=admin.id).all()
    if request.method == 'POST':
        pid = request.form.get('professional_id', type=int)
        if pid:
            return redirect(url_for('main.cliente_periodo', salao_slug=salao_slug, service_id=service_id, professional_id=pid, location_id=location_id))
    back_url = url_for('main.salao_servico', salao_slug=salao_slug, location_id=location_id) if is_basic(admin) and location_id else url_for('main.salao_servico', salao_slug=salao_slug)
    return render_template('cliente_profissional.html', professionals=pros, salao_slug=salao_slug, back_url=back_url)


@main.route('/<salao_slug>/periodo', methods=['GET', 'POST'])
def cliente_periodo(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    service_id = request.args.get('service_id', type=int)
    professional_id = request.args.get('professional_id', type=int)
    location_id = request.args.get('location_id', type=int)
    if request.method == 'POST':
        period = request.form.get('period')
        if period in ('manha', 'tarde', 'noite'):
            return redirect(url_for('main.cliente_data', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, period=period))
    back_url = url_for('main.cliente_profissional', salao_slug=salao_slug, service_id=service_id, location_id=location_id)
    return render_template('cliente_periodo.html', salao_slug=salao_slug, back_url=back_url)


def _period_range(period: str):
    # retorna (start_hour, end_hour) inclusivo de início, exclusivo de fim
    if period == 'manha':
        return (8, 12)
    if period == 'tarde':
        return (12, 18)
    if period == 'noite':
        return (18, 22)
    return (8, 22)


@main.route('/<salao_slug>/data', methods=['GET', 'POST'])
def cliente_data(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    service_id = request.args.get('service_id', type=int)
    professional_id = request.args.get('professional_id', type=int)
    location_id = request.args.get('location_id', type=int)
    period = request.args.get('period')
    service = Service.query.filter_by(id=service_id, admin_id=admin.id).first_or_404()
    prof = Professional.query.filter_by(id=professional_id, admin_id=admin.id).first_or_404()
    start_h, end_h = _period_range(period)
    # próximos 14 dias com pelo menos um slot disponível
    days = []
    today = datetime.today().date()
    for i in range(0, 14):
        d = today + timedelta(days=i)
        # procura se existe ao menos 1 slot dentro do período
        cur = datetime.combine(d, datetime.strptime(f"{start_h:02d}:00", '%H:%M').time())
        end_dt = datetime.combine(d, datetime.strptime(f"{end_h:02d}:00", '%H:%M').time())
        ok = False
        while cur + timedelta(minutes=service.duration) <= end_dt:
            if _is_slot_available(prof, cur, service.duration, admin, location_id):
                ok = True
                break
            cur += timedelta(minutes=15)
        if ok:
            days.append(d)
    if request.method == 'POST':
        date_str = request.form.get('date')
        try:
            sel = datetime.strptime(date_str, '%Y-%m-%d').date()
        except Exception:
            sel = None
        if sel:
            return redirect(url_for('main.cliente_horario', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, period=period, date=sel.strftime('%Y-%m-%d')))
    back_url = url_for('main.cliente_periodo', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id)
    return render_template('cliente_data.html', days=days, salao_slug=salao_slug, back_url=back_url)


@main.route('/<salao_slug>/horario', methods=['GET', 'POST'])
def cliente_horario(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    service_id = request.args.get('service_id', type=int)
    professional_id = request.args.get('professional_id', type=int)
    location_id = request.args.get('location_id', type=int)
    period = request.args.get('period')
    date_str = request.args.get('date')
    service = Service.query.filter_by(id=service_id, admin_id=admin.id).first_or_404()
    prof = Professional.query.filter_by(id=professional_id, admin_id=admin.id).first_or_404()
    try:
        d = datetime.strptime(date_str, '%Y-%m-%d').date()
    except Exception:
        return redirect(url_for('main.cliente_data', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, period=period))
    start_h, end_h = _period_range(period)
    # gera slots de 15min dentro do período
    slots = []
    cur = datetime.combine(d, datetime.strptime(f"{start_h:02d}:00", '%H:%M').time())
    end_dt = datetime.combine(d, datetime.strptime(f"{end_h:02d}:00", '%H:%M').time())
    while cur + timedelta(minutes=service.duration) <= end_dt:
        if _is_slot_available(prof, cur, service.duration, admin, location_id):
            slots.append(cur.strftime('%H:%M'))
        cur += timedelta(minutes=15)
    if request.method == 'POST':
        horario = request.form.get('horario')
        if horario:
            return redirect(url_for('main.confirmar_agendamento', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, date=d.strftime('%Y-%m-%d'), horario=horario))
    back_url = url_for('main.cliente_data', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, period=period)
    return render_template('cliente_horario.html', slots=slots, salao_slug=salao_slug, back_url=back_url)


@main.route('/<salao_slug>/confirmar', methods=['GET', 'POST'])
def confirmar_agendamento(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    service_id = request.args.get('service_id', type=int)
    professional_id = request.args.get('professional_id', type=int)
    location_id = request.args.get('location_id', type=int)
    date_str = request.args.get('date')
    horario = request.args.get('horario')
    service = Service.query.filter_by(id=service_id, admin_id=admin.id).first_or_404()
    professional = Professional.query.filter_by(id=professional_id, admin_id=admin.id).first_or_404()
    try:
        appt_dt = datetime.strptime(f"{date_str} {horario}", '%Y-%m-%d %H:%M')
    except Exception:
        return redirect(url_for('main.cliente_horario', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, date=date_str))
    if request.method == 'POST':
        # cria customer a partir do cookie
        cust_id = getattr(g, 'customer_id', None)
        cust = Customer.query.get(cust_id) if cust_id else None
        if not cust:
            return redirect(url_for('main.login_phone_screen', salao_slug=salao_slug))
        if not _is_slot_available(professional, appt_dt, service.duration, admin, location_id):
            flash('O horário selecionado não está mais disponível.', 'warning')
            return redirect(url_for('main.cliente_horario', salao_slug=salao_slug, service_id=service_id, professional_id=professional_id, location_id=location_id, date=date_str))
        appt = Appointment(customer_id=cust.id, professional_id=professional.id, service_id=service.id, location_id=location_id, appointment_time=appt_dt, ativo=True)
        db.session.add(appt)
        db.session.commit()
        return render_template('agendamento_sucesso.html', salao_slug=salao_slug)
    data_fmt = appt_dt.strftime('%d/%m/%Y')
    hora_fmt = appt_dt.strftime('%H:%M')
    return render_template('confirmar_agendamento.html', service=service, professional=professional, data=data_fmt, horario=hora_fmt)


@main.route('/<salao_slug>/meus-agendamentos')
def meus_agendamentos_cliente(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    cust_id = getattr(g, 'customer_id', None)
    if not cust_id:
        return redirect(url_for('main.login_phone_screen', salao_slug=salao_slug))
    # Seleciona agendamentos deste cliente com profissionais do admin
    ags = Appointment.query.join(Professional).filter(
        Appointment.customer_id == cust_id,
        Professional.admin_id == admin.id,
        Appointment.ativo == True
    ).options(joinedload(Appointment.service), joinedload(Appointment.professional), joinedload(Appointment.location)).order_by(Appointment.appointment_time.asc()).all()
    return render_template('meus_agendamentos_cliente.html', agendamentos=ags, salao_slug=salao_slug)


@main.route('/<salao_slug>/cancelar/<int:agendamento_id>', methods=['POST'])
def cancelar_agendamento_cliente(salao_slug, agendamento_id):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not _public_link_allowed(admin):
        abort(404)
    redir = _require_customer_auth(salao_slug)
    if redir:
        return redir
    cust_id = getattr(g, 'customer_id', None)
    ag = Appointment.query.join(Professional).filter(
        Appointment.id == agendamento_id,
        Appointment.customer_id == cust_id,
        Professional.admin_id == admin.id
    ).first_or_404()
    ag.ativo = False
    db.session.commit()
    flash('Agendamento cancelado.', 'success')
    return redirect(url_for('main.meus_agendamentos_cliente', salao_slug=salao_slug))