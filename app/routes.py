from flask import render_template, redirect, url_for, flash, request, Blueprint, abort, session, jsonify, g, current_app, make_response
from flask_login import login_user, logout_user, login_required, current_user
from . import db, login_manager
from .models import User, Professional, Service, Appointment, Customer, ProfessionalSchedule, Location, LocationSchedule
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

@main.route('/dashboard/add_event', endpoint='dashboard_add_event', methods=['POST'])
@login_required
def dashboard_add_event():
    # Apenas salva um bloqueio ou evento simples (mock)
    flash('Evento/bloqueio adicionado (mock).', 'success')
    return redirect(url_for('main.dashboard'))

@main.route('/dashboard/profile', endpoint='dashboard_profile', methods=['GET'])
@login_required
def dashboard_profile():
    if current_user.role != 'admin':
        abort(403)
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


@main.route('/api/auth/check_phone', methods=['POST'])
def api_check_phone():
    data = request.get_json(silent=True) or {}
    phone = (data.get('phone') or '').strip()
    salao_slug = (data.get('salao_slug') or '').strip()
    if not (phone and salao_slug):
        return jsonify({'ok': False, 'error': 'missing_parameters'}), 400
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404

    # Check local DB for customer linked to this admin
    customer = Customer.query.filter_by(phone=phone).first()
    exists_local = False
    customer_name = None
    if customer and admin in customer.admins:
        exists_local = True
        customer_name = customer.name

    return jsonify({'ok': True, 'exists': exists_local, 'name': customer_name})


@main.route('/api/auth/login', methods=['POST'])
def api_customer_login():
    data = request.get_json(silent=True) or {}
    phone = (data.get('phone') or '').strip()
    password = (data.get('password') or '').strip()
    salao_slug = (data.get('salao_slug') or '').strip()
    if not (phone and password and salao_slug):
        return jsonify({'ok': False, 'error': 'missing_parameters'}), 400
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404
    customer = Customer.query.filter_by(phone=phone).first()
    if not customer or admin not in customer.admins or not customer.check_password(password):
        return jsonify({'ok': False, 'error': 'invalid_credentials'}), 401
    jwt_token = _create_customer_jwt(customer.id, customer.name, admin.id)
    resp = jsonify({'ok': True})
    max_age = 60 * 60 * 24 * 180
    resp.set_cookie('customer_jwt', jwt_token, max_age=max_age, httponly=True, secure=False, samesite='Lax', path='/')
    return resp


@main.route('/api/auth/register', methods=['POST'])
def api_register_customer():
    data = request.get_json(silent=True) or {}
    salao_slug = (data.get('salao_slug') or '').strip()
    first_name = (data.get('firstName') or '').strip()
    last_name = (data.get('lastName') or '').strip()
    email = (data.get('email') or '').strip()
    birthdate = (data.get('birthdate') or '').strip()
    phone = (data.get('phone') or '').strip()
    password = (data.get('password') or '').strip()
    if not (salao_slug and first_name and birthdate and phone and password):
        return jsonify({'ok': False, 'error': 'missing_parameters'}), 400
    admin = User.query.filter_by(username=salao_slug, role='admin').first()
    if not admin:
        return jsonify({'ok': False, 'error': 'salon_not_found'}), 404
    try:
        bd = datetime.strptime(birthdate, '%Y-%m-%d').date()
    except Exception:
        return jsonify({'ok': False, 'error': 'invalid_birthdate'}), 400
    full_name = f"{first_name} {last_name}".strip()
    customer = Customer.query.filter_by(phone=phone).first()
    if not customer:
        customer = Customer(name=full_name, birthdate=bd, phone=phone, email=email or None)
        customer.set_password(password)
        db.session.add(customer)
        db.session.commit()
    else:
        # If already exists, ensure linked and set/overwrite password only if empty
        if not customer.password:
            customer.set_password(password)
        if email:
            customer.email = email
        if full_name and customer.name != full_name:
            customer.name = full_name
        db.session.commit()
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

    # Try to extract preapproval_id from multiple possible fields
    preapproval_id = None
    # Direct notification
    if 'id' in data and (data.get('type') == 'preapproval' or data.get('type') == 'subscription'):
        preapproval_id = data['id']
    # Sometimes Mercado Pago sends 'data' field with 'id'
    if not preapproval_id and isinstance(data.get('data'), dict):
        if 'id' in data['data']:
            preapproval_id = data['data']['id']
    # Sometimes 'resource' field
    if not preapproval_id and isinstance(data.get('resource'), dict):
        if 'id' in data['resource']:
            preapproval_id = data['resource']['id']
    # Try query string
    if not preapproval_id:
        preapproval_id = request.args.get('id')
    # Try 'subscription_id' field
    if not preapproval_id and 'subscription_id' in data:
        preapproval_id = data['subscription_id']

    if not preapproval_id:
        current_app.logger.warning(f"Webhook: preapproval_id not found. Payload: {data}, Args: {request.args}")
        return jsonify({'ok': False, 'error': 'preapproval_id not found'}), 400

    # Busca preapproval e atualiza usuário
    try:
        preapproval = _mp_get_preapproval(preapproval_id)
        # Localiza usuário pelo subscription_id
        user = User.query.filter_by(subscription_id=preapproval_id).first()
        if user:
            _apply_preapproval_to_user(user, preapproval)
            db.session.commit()
            current_app.logger.info(f"Webhook: assinatura atualizada para user_id={user.id}, status={user.subscription_status}")
            return jsonify({'ok': True, 'user_id': user.id, 'status': user.subscription_status})
        else:
            current_app.logger.warning(f"Webhook: user not found for subscription_id={preapproval_id}")
            return jsonify({'ok': False, 'error': 'user not found'}), 404
    except Exception as e:
        current_app.logger.exception('Erro no webhook Mercado Pago: %s', e)
        return jsonify({'ok': False, 'error': str(e)}), 500

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
    profissional_id = request.args.get('profissional_id', type=int)
    status = request.args.get('status', default='ativos')
    profissionais = Professional.query.filter_by(admin_id=current_user.id).all()
    servicos = Service.query.filter_by(admin_id=current_user.id).all()
    locations = Location.query.filter_by(admin_id=current_user.id).all()
    agendamentos = []
    # Adiciona timedelta ao contexto para o template
    return render_template('dashboard_agenda.html', data=data, profissional_id=profissional_id,
                           status=status, profissionais=profissionais, servicos=servicos,
                           locations=locations, agendamentos=agendamentos, timedelta=timedelta)

@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Você saiu da conta.', 'success')
    return redirect(url_for('main.login'))

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

@main.route('/locations', endpoint='locations_list', methods=['GET'])
@login_required
def locations_list():
    if current_user.role != 'admin':
        abort(403)
    locs = Location.query.options(joinedload(Location.schedules)).filter_by(admin_id=current_user.id).all()
    return render_template('locations_list.html', locations=locs)

@main.route('/professionals/add', endpoint='add_professional', methods=['GET','POST'])
@login_required
def add_professional():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        if not name:
            flash('Nome do profissional é obrigatório.', 'danger')
            return redirect(url_for('main.add_professional'))
        prof = Professional(name=name, admin_id=current_user.id)
        db.session.add(prof)
        db.session.commit()
        flash('Profissional adicionado.', 'success')
        return redirect(url_for('main.professionals_list'))
    return render_template('add_professional.html', back_url=url_for('main.professionals_list'))

@main.route('/services/add', endpoint='add_service', methods=['GET','POST'])
@login_required
def add_service():
    if current_user.role != 'admin':
        abort(403)
    pros = Professional.query.filter_by(admin_id=current_user.id).all()
    locs = Location.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        duration = request.form.get('duration', type=int)
        price = request.form.get('price', type=float)
        if not (name and duration and price is not None):
            flash('Preencha nome, duração e preço.', 'danger')
            return render_template('add_service.html', professionals=pros, locations=locs)
        s = Service(name=name, duration=duration, price=price, admin_id=current_user.id)
        db.session.add(s)
        db.session.flush()
        # associações
        pro_ids = request.form.getlist('professional_ids')
        if pro_ids:
            sel_pros = Professional.query.filter(Professional.id.in_(pro_ids), Professional.admin_id==current_user.id).all()
            for p in sel_pros:
                s.professionals.append(p)
        loc_ids = request.form.getlist('location_ids')
        if loc_ids:
            sel_locs = Location.query.filter(Location.id.in_(loc_ids), Location.admin_id==current_user.id).all()
            for l in sel_locs:
                s.locations.append(l)
        db.session.commit()
        flash('Serviço criado.', 'success')
        return redirect(url_for('main.services_list'))
    return render_template('add_service.html', professionals=pros, locations=locs)

@main.route('/locations/add', endpoint='add_location', methods=['GET','POST'])
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
        db.session.flush()
        # Horários
        workdays = request.form.getlist('workdays')
        for wd in workdays:
            i = int(wd)
            st = request.form.get(f'start_{i}')
            en = request.form.get(f'end_{i}')
            bs = request.form.get(f'break_start_{i}')
            be = request.form.get(f'break_end_{i}')
            if st and en:
                ls = LocationSchedule(location_id=loc.id,
                                      weekday=i,
                                      start_time=datetime.strptime(st, '%H:%M').time(),
                                      end_time=datetime.strptime(en, '%H:%M').time(),
                                      break_start=datetime.strptime(bs, '%H:%M').time() if bs else None,
                                      break_end=datetime.strptime(be, '%H:%M').time() if be else None)
                db.session.add(ls)
        db.session.commit()
        flash('Local criado.', 'success')
        return redirect(url_for('main.locations_list'))
    return render_template('add_location.html')

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
    if status in ('authorized', 'active', 'approved'):
        user.subscription_status = 'active'
    elif status in ('paused', 'cancelled', 'canceled'):
        user.subscription_status = 'canceled'
    elif status in ('expired',):
        user.subscription_status = 'expired'
    else:
        user.subscription_status = status or 'pending'
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
        current_user.subscription_status = 'pending'
        current_user.plan = plan_key
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