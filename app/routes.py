from flask import render_template, redirect, url_for, flash, request, Blueprint, abort, session, jsonify, g, current_app
from flask_login import login_user, logout_user, login_required, current_user
from . import db, login_manager
from .models import User, Professional, Service, Appointment, Customer, ProfessionalSchedule, Location, LocationSchedule
from .models import Location
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, or_
from .forms import LoginForm, RegistrationForm, AppointmentForm
from sqlalchemy.orm import joinedload
import os
import jwt
from werkzeug.utils import secure_filename

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    return render_template('index.html')


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
            plan="free"
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
        flash('Conta criada com sucesso! Você pode agora fazer login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role != 'admin':
        abort(403)

    # Plano BASIC: garante o profissional padrão
    if is_basic(current_user):
        ensure_default_professional(current_user)

    # Filtros
    data_str = request.args.get('data')
    profissional_id = request.args.get('profissional_id', type=int)
    status = request.args.get('status', 'ativos')

    # Data padrão: hoje
    if data_str:
        data = datetime.strptime(data_str, "%Y-%m-%d").date()
    else:
        data = datetime.today().date()

    # Profissionais do salão
    profissionais = Professional.query.filter_by(admin_id=current_user.id).all()

    # Filtro de profissional
    if profissional_id:
        profissional = Professional.query.filter_by(id=profissional_id, admin_id=current_user.id).first()
        if not profissional:
            abort(404)
        profissionais_ids = [profissional.id]
    else:
        profissionais_ids = [p.id for p in profissionais]

    # Filtro de status
    if status == 'cancelados':
        status_filter = (Appointment.ativo == False)
    else:
        status_filter = (Appointment.ativo == True)

    # Agendamentos do dia e profissionais filtrados
    agendamentos = Appointment.query \
        .filter(
            Appointment.professional_id.in_(profissionais_ids),
            func.date(Appointment.appointment_time) == data,
            status_filter
        ) \
        .options(joinedload(Appointment.professional), joinedload(Appointment.service), joinedload(Appointment.customer), joinedload(Appointment.location)) \
        .order_by(Appointment.appointment_time.asc()) \
        .all()

    # Para mostrar horários vagos, pegue todos os serviços para saber as durações
    servicos = Service.query.filter_by(admin_id=current_user.id).all()

    # Navegação de datas
    prev_date = (data - timedelta(days=1)).strftime("%Y-%m-%d")
    next_date = (data + timedelta(days=1)).strftime("%Y-%m-%d")
    data = data.date() if isinstance(data, datetime) else data

    # Em plano Basic, carregar Locais para o modal
    locations = []
    if is_basic(current_user):
        locations = Location.query.filter_by(admin_id=current_user.id).all()

    return render_template(
        'dashboard_agenda.html',
        profissionais=profissionais,
        profissional_id=profissional_id,
        agendamentos=agendamentos,
        servicos=servicos,
        locations=locations,
        data=data,
        prev_date=prev_date,
        next_date=next_date,
        status=status,
        timedelta=timedelta
    )

@main.route('/schedule', methods=['GET', 'POST'])
def schedule():
    form = AppointmentForm()
    form.service.choices = [(s.id, s.name) for s in Service.query.all()]
    form.professional.choices = [(p.id, p.name) for p in Professional.query.all()]
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to register or log in to complete your appointment.', 'info')
            return redirect(url_for('main.login'))
        # Usuário logado: salva o agendamento
        appointment = Appointment(
            user_id=current_user.id,
            professional_id=form.professional.data,
            service_id=form.service.data,
            appointment_time=datetime.combine(form.date.data, form.time.data)
        )
        db.session.add(appointment)
        db.session.commit()
        flash('Appointment scheduled!', 'success')
        return redirect(url_for('main.my_appointments'))
    return render_template('schedule.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.index'))

@main.route('/add_professional', methods=['GET', 'POST'])
@login_required
def add_professional():
    if current_user.role != 'admin':
        abort(403)
    # Regras de plano
    if is_basic(current_user):
        flash('Seu plano (Basic) não permite adicionar profissionais. Gerencie horários pelos Locais.', 'warning')
        return redirect(url_for('main.professionals_list'))
    if is_free(current_user):
        count = Professional.query.filter_by(admin_id=current_user.id).count()
        if count >= 1:
            flash('Plano Free permite apenas 1 profissional.', 'warning')
            return redirect(url_for('main.professionals_list'))
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            new_prof = Professional(name=name, admin_id=current_user.id)
            db.session.add(new_prof)
            db.session.commit()

            # Após salvar o Professional:
            workdays = request.form.getlist('workdays')
            for i in range(7):
                if str(i) in workdays:
                    start = request.form.get(f'start_{i}')
                    end = request.form.get(f'end_{i}')
                    break_start = request.form.get(f'break_start_{i}') or None
                    break_end = request.form.get(f'break_end_{i}') or None
                    if start and end:
                        schedule = ProfessionalSchedule(
                            professional_id=new_prof.id,
                            weekday=i,
                            start_time=start,
                            end_time=end,
                            break_start=break_start,
                            break_end=break_end
                        )
                        db.session.add(schedule)
            db.session.commit()

            flash('Professional added successfully!', 'success')
            return redirect(url_for('main.dashboard'))
        flash('Name is required.', 'danger')
    
    return render_template('add_professional.html', back_url=url_for('main.professionals_list'))
@main.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if current_user.role != 'admin':
        abort(403)
    professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    locations = []
    if is_basic(current_user):
        # Garante que apenas o profissional padrão apareça e carrega Locais
        professionals = [ensure_default_professional(current_user)]
        locations = Location.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = request.form.get('name')
        duration = request.form.get('duration')
        price = request.form.get('price')
        professional_ids = request.form.getlist('professional_ids')
        location_ids = request.form.getlist('location_ids') if is_basic(current_user) else []
        if not (name and duration and price and professional_ids):
            flash('All fields are required.', 'danger')
        else:
            new_service = Service(
                name=name,
                duration=int(duration),
                price=float(price),
                admin_id=current_user.id
            )
            # Associa os profissionais selecionados
            new_service.professionals = Professional.query.filter(Professional.id.in_(professional_ids)).all()
            # No BASIC, associa Locais selecionados
            if is_basic(current_user) and location_ids:
                new_service.locations = Location.query.filter(
                    Location.admin_id == current_user.id,
                    Location.id.in_(location_ids)
                ).all()
            db.session.add(new_service)
            db.session.commit()
            flash('Service added successfully!', 'success')
            return redirect(url_for('main.dashboard'))
    return render_template('add_service.html', professionals=professionals, locations=locations)

@main.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    if is_basic(current_user):
        professionals = [ensure_default_professional(current_user)]
        locations = Location.query.filter_by(admin_id=current_user.id).all()
        selected_location_ids = [str(l.id) for l in service.locations]
    else:
        professionals = Professional.query.filter_by(admin_id=current_user.id).all()
        locations = []
        selected_location_ids = []
    if request.method == 'POST':
        name = request.form.get('name')
        duration = request.form.get('duration', type=int)
        price = request.form.get('price', type=float)
        professional_ids = request.form.getlist('professional_ids')
        location_ids = request.form.getlist('location_ids') if is_basic(current_user) else []
        if name and duration and price is not None:
            service.name = name
            service.duration = duration
            service.price = price
            # Atualiza profissionais
            service.professionals = [Professional.query.get(int(pid)) for pid in professional_ids]
            # Atualiza Locais no BASIC
            if is_basic(current_user):
                service.locations = Location.query.filter(
                    Location.admin_id == current_user.id,
                    Location.id.in_(location_ids)
                ).all()
            db.session.commit()
            flash('Serviço atualizado com sucesso!', 'success')
            return redirect(url_for('main.services_list'))
        flash('Preencha todos os campos.', 'danger')
    selected_ids = [str(p.id) for p in service.professionals]
    return render_template('edit_service.html', service=service, professionals=professionals, selected_ids=selected_ids, locations=locations, selected_location_ids=selected_location_ids)

@main.route('/delete_service/<int:id>')
@login_required
def delete_service(id):
    return f"Delete Service {id} - Em construção"

@main.route('/edit_professional/<int:professional_id>', methods=['GET', 'POST'])
@login_required
def edit_professional(professional_id):
    if is_basic(current_user):
        flash('Seu plano (Basic) não permite editar profissionais.', 'warning')
        return redirect(url_for('main.professionals_list'))
    professional = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first_or_404()
    schedules = ProfessionalSchedule.query.filter_by(professional_id=professional.id).all()
    dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sab', 'Dom']
    # Prepara dados para o template
    horarios = {sch.weekday: sch for sch in schedules}
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            professional.name = name
            # Remove horários antigos
            ProfessionalSchedule.query.filter_by(professional_id=professional.id).delete()
            db.session.commit()
            # Adiciona novos horários
            workdays = request.form.getlist('workdays')
            for i in range(7):
                if str(i) in workdays:
                    start = request.form.get(f'start_{i}')
                    end = request.form.get(f'end_{i}')
                    break_start = request.form.get(f'break_start_{i}') or None
                    break_end = request.form.get(f'break_end_{i}') or None
                    if start and end:
                        schedule = ProfessionalSchedule(
                            professional_id=professional.id,
                            weekday=i,
                            start_time=start,
                            end_time=end,
                            break_start=break_start,
                            break_end=break_end
                        )
                        db.session.add(schedule)
            db.session.commit()
            flash('Profissional atualizado com sucesso!', 'success')
            return redirect(url_for('main.professionals_list'))
        flash('Nome é obrigatório.', 'danger')
    return render_template('edit_professional.html', professional=professional, dias=dias, horarios=horarios)

@main.route('/delete_professional/<int:professional_id>', methods=['POST'])
@login_required
def delete_professional(professional_id):
    if is_basic(current_user):
        flash('Seu plano (Basic) não permite remover profissionais.', 'warning')
        return redirect(url_for('main.professionals_list'))
    professional = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first_or_404()
    db.session.delete(professional)
    db.session.commit()
    flash('Profissional excluído com sucesso!', 'success')
    return redirect(url_for('main.professionals_list'))

@main.route('/confirm_delete_professional/<int:professional_id>', methods=['GET', 'POST'])
@login_required
def confirm_delete_professional(professional_id):
    professional = Professional.query.filter_by(id=professional_id, admin_id=current_user.id).first_or_404()
    if request.method == 'POST':
        # Exclui agendamentos e horários
        Appointment.query.filter_by(professional_id=professional.id).delete()
        ProfessionalSchedule.query.filter_by(professional_id=professional.id).delete()
        db.session.delete(professional)
        db.session.commit()
        flash('Profissional e todos os agendamentos excluídos!', 'success')
        return redirect(url_for('main.professionals_list'))
    return render_template('confirm_delete_professional.html', professional=professional)

@main.route('/my_appointments')
@login_required
def my_appointments():
    appointments = Appointment.query.filter_by(admin_id=current_user.id).all()
    return render_template('my_appointments.html', appointments=appointments)

@main.route('/<salao_slug>', methods=['GET', 'POST'])
def salao_home(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    services = Service.query.filter_by(admin_id=admin.id).all()
    professionals = Professional.query.filter_by(admin_id=admin.id).all()
    return render_template('salao_home.html', admin=admin, services=services, professionals=professionals)

@main.route('/<salao_slug>/cliente', methods=['GET', 'POST'])
def customer_login(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if request.method == 'POST':
        phone = request.form.get('phone')
        name = request.form.get('name')
        birthdate = request.form.get('birthdate')
        customer = Customer.query.filter_by(phone=phone).first()
        if not customer:
            customer = Customer(name=name, phone=phone, birthdate=birthdate)
            db.session.add(customer)
            db.session.commit()
        if admin not in customer.admins:
            customer.admins.append(admin)
            db.session.commit()
        session['customer_id'] = customer.id
        session['admin_id'] = admin.id
        # Redireciona para a tela de opções
        return redirect(url_for('main.cliente_opcoes', salao_slug=salao_slug))
    return render_template('cliente_bemvindo.html', salao_slug=salao_slug)

@main.route('/<salao_slug>/opcoes')
def cliente_opcoes(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    # Apenas no plano BASIC oferecemos locais
    has_locations = False
    if is_basic(admin):
        has_locations = Location.query.filter_by(admin_id=admin.id).count() > 0
    return render_template('cliente_opcoes.html', salao_slug=salao_slug, has_locations=has_locations)

@main.route('/<salao_slug>/servico', methods=['GET', 'POST'])
def salao_servico(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    services = Service.query.filter_by(admin_id=admin.id).all()
    if request.method == 'POST':
        service_id = request.form.get('service_id')
        session['service_id'] = service_id
        # Agora escolhemos o local depois do serviço, quando aplicável
        if is_basic(admin) and Location.query.filter_by(admin_id=admin.id).count() > 0:
            return redirect(url_for('main.salao_local', salao_slug=salao_slug))
        return redirect(url_for('main.salao_profissional', salao_slug=salao_slug))
    return render_template(
        'cliente_servico.html',
        services=services,
        salao_slug=salao_slug,
        back_url=url_for('main.salao_home', salao_slug=salao_slug)
    )


@main.route('/<salao_slug>/local', methods=['GET','POST'])
def salao_local(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not is_basic(admin):
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    # Exige serviço escolhido antes
    service_id = session.get('service_id')
    if not service_id:
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    service = Service.query.filter_by(id=service_id, admin_id=admin.id).first_or_404()
    # Mostrar somente os locais onde o serviço é oferecido
    locations = service.locations if service.locations else []
    if not locations:
        flash('Este serviço ainda não está associado a nenhum local.', 'warning')
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    if request.method == 'POST':
        loc_id = request.form.get('location_id')
        session['location_id'] = int(loc_id) if loc_id else None
        return redirect(url_for('main.salao_profissional', salao_slug=salao_slug))
    return render_template('cliente_local.html', locations=locations, salao_slug=salao_slug, back_url=url_for('main.cliente_opcoes', salao_slug=salao_slug))

@main.route('/<salao_slug>/profissional', methods=['GET', 'POST'])
def salao_profissional(salao_slug):
    service_id = session.get('service_id')
    if not service_id:
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    service = Service.query.get_or_404(service_id)
    professionals = service.professionals
    if request.method == 'POST':
        professional_id = request.form.get('professional_id')
        session['professional_id'] = professional_id
        return redirect(url_for('main.salao_periodo', salao_slug=salao_slug))
    return render_template(
        'cliente_profissional.html',
        professionals=professionals,
        salao_slug=salao_slug,
        back_url=url_for('main.salao_servico', salao_slug=salao_slug)
    )

@main.route('/<salao_slug>/periodo', methods=['GET', 'POST'])
def salao_periodo(salao_slug):
    if request.method == 'POST':
        period = request.form.get('period')
        session['period'] = period
        return redirect(url_for('main.salao_data', salao_slug=salao_slug))
    return render_template(
        'cliente_periodo.html',
        salao_slug=salao_slug,
        back_url=url_for('main.salao_profissional', salao_slug=salao_slug)
    )

@main.route('/<salao_slug>/data', methods=['GET', 'POST'])
def salao_data(salao_slug):
    service_id = session.get('service_id')
    professional_id = session.get('professional_id')
    period = session.get('period')
    if not (service_id and professional_id and period):
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    service = Service.query.get_or_404(service_id)
    # No BASIC, se houver local selecionado, verificar se o serviço é oferecido nele
    admin = User.query.get(service.admin_id)
    if is_basic(admin):
        loc_id = session.get('location_id')
        if loc_id and not any(l.id == int(loc_id) for l in service.locations):
            flash('Este serviço não é oferecido no local selecionado. Escolha outro local ou serviço.', 'warning')
            return redirect(url_for('main.salao_local', salao_slug=salao_slug))
    professional = Professional.query.get_or_404(professional_id)
    today = datetime.today().date()
    days = []
    for i in range(7):
        day = today + timedelta(days=i)
        if tem_slot_disponivel(day, period, service, professional):
            days.append(day)
    if request.method == 'POST':
        date = request.form.get('date')
        session['date'] = date
        return redirect(url_for('main.escolher_horario', salao_slug=salao_slug))
    return render_template(
        'cliente_data.html',
        days=days,
        salao_slug=salao_slug,
        back_url=url_for('main.salao_periodo', salao_slug=salao_slug)
    )

def tem_slot_disponivel(day, period, service, professional):
    # Busca os horários de trabalho do profissional para o dia da semana
    weekday = day.weekday()
    schedules = ProfessionalSchedule.query.filter_by(professional_id=professional.id, weekday=weekday).all()
    duration = service.duration

    # Regras de plano: em BASIC podemos usar apenas janela do Local
    admin = User.query.get(professional.admin_id)
    # Se for BASIC e houver local selecionado, validar se o serviço é oferecido nesse local
    if is_basic(admin):
        sel_loc = session.get('location_id')
        if sel_loc and not any(l.id == int(sel_loc) for l in service.locations):
            return False
    location_id = session.get('location_id') if is_basic(admin) else None
    loc_schedules = []
    if location_id:
        loc_schedules = LocationSchedule.query.filter_by(location_id=location_id, weekday=weekday).all()

    # Se não trabalha nesse dia, em BASIC tentamos usar janela do local
    if not schedules:
        if is_basic(admin) and loc_schedules:
            class S: pass
            schedules = []
            for lsch in loc_schedules:
                s = S()
                s.start_time = lsch.start_time
                s.end_time = lsch.end_time
                s.break_start = lsch.break_start
                s.break_end = lsch.break_end
                schedules.append(s)
        else:
            return False

    agendamentos = Appointment.query.filter(
        Appointment.professional_id == professional.id,
        func.date(Appointment.appointment_time) == day,
        Appointment.ativo == True
    ).all()
    ocupados = []
    for ag in agendamentos:
        ag_start = ag.appointment_time
        ag_end = ag_start + timedelta(minutes=Service.query.get(ag.service_id).duration)
        ocupados.append((ag_start, ag_end))

    # loc_schedules já calculados acima conforme plano

    for sch in schedules:
        slot_time = datetime.combine(day, sch.start_time)
        end_time = datetime.combine(day, sch.end_time)
        while slot_time + timedelta(minutes=duration) <= end_time:
            # Pula intervalo de pausa, se houver
            if sch.break_start and sch.break_end:
                break_start = datetime.combine(day, sch.break_start)
                break_end = datetime.combine(day, sch.break_end)
                if slot_time >= break_start and slot_time < break_end:
                    slot_time = break_end
                    continue
            # Check location window if present
            if loc_schedules:
                inside_any = False
                for lsch in loc_schedules:
                    l_start = datetime.combine(day, lsch.start_time)
                    l_end = datetime.combine(day, lsch.end_time)
                    if lsch.break_start and lsch.break_end:
                        lb_start = datetime.combine(day, lsch.break_start)
                        lb_end = datetime.combine(day, lsch.break_end)
                    else:
                        lb_start = lb_end = None
                    # slot must be within location open hours and not in location break
                    if slot_time >= l_start and (slot_time + timedelta(minutes=duration)) <= l_end:
                        if lb_start and lb_end and slot_time >= lb_start and slot_time < lb_end:
                            pass
                        else:
                            inside_any = True
                            break
                if not inside_any:
                    slot_time += timedelta(minutes=15)
                    continue
            livre = True
            slot_end = slot_time + timedelta(minutes=duration)
            for ag_start, ag_end in ocupados:
                if (slot_time < ag_end and slot_end > ag_start):
                    livre = False
                    break
            if livre:
                return True
            slot_time += timedelta(minutes=15)
    return False

@main.route('/<salao_slug>/horario', methods=['GET', 'POST'])
def escolher_horario(salao_slug):
    service_id = session.get('service_id')
    professional_id = session.get('professional_id')
    date = session.get('date')
    period = session.get('period')
    customer_id = session.get('customer_id')
    if not (service_id and professional_id and date and period and customer_id):
        return redirect(url_for('main.salao_servico', salao_slug=salao_slug))
    service = Service.query.get_or_404(service_id)
    professional = Professional.query.get_or_404(professional_id)
    duration = service.duration
    date_obj = datetime.strptime(str(date), "%Y-%m-%d")
    weekday = date_obj.weekday()
    slots = []

    # Busca os horários de trabalho do profissional para o dia da semana
    schedules = ProfessionalSchedule.query.filter_by(professional_id=professional.id, weekday=weekday).all()

    agendamentos = Appointment.query.filter(
        Appointment.professional_id == professional.id,
        func.date(Appointment.appointment_time) == date,
        Appointment.ativo == True
    ).all()
    ocupados = []
    for ag in agendamentos:
        ag_start = ag.appointment_time
        ag_end = ag_start + timedelta(minutes=Service.query.get(ag.service_id).duration)
        ocupados.append((ag_start, ag_end))

    # Regras de plano: em BASIC usamos local; nos demais ignoramos local
    admin = User.query.get(professional.admin_id)
    # Se for BASIC, garantir que o serviço é disponível no local escolhido
    if is_basic(admin):
        sel_loc = session.get('location_id')
        if sel_loc and not any(l.id == int(sel_loc) for l in service.locations):
            flash('Este serviço não é oferecido no local selecionado.', 'warning')
            return redirect(url_for('main.salao_local', salao_slug=salao_slug))
    location_id = session.get('location_id') if is_basic(admin) else None
    loc_schedules = []
    if location_id:
        loc_schedules = LocationSchedule.query.filter_by(location_id=location_id, weekday=weekday).all()

    if not schedules:
        if is_basic(admin) and loc_schedules:
            class S: pass
            schedules = []
            for lsch in loc_schedules:
                s = S()
                s.start_time = lsch.start_time
                s.end_time = lsch.end_time
                s.break_start = lsch.break_start
                s.break_end = lsch.break_end
                schedules.append(s)
        else:
            schedules = []

    for sch in schedules:
        slot_time = date_obj.replace(hour=sch.start_time.hour, minute=sch.start_time.minute)
        end_time = date_obj.replace(hour=sch.end_time.hour, minute=sch.end_time.minute)
        while slot_time + timedelta(minutes=duration) <= end_time:
            # Pula intervalo de pausa, se houver
            if sch.break_start and sch.break_end:
                break_start = date_obj.replace(hour=sch.break_start.hour, minute=sch.break_start.minute)
                break_end = date_obj.replace(hour=sch.break_end.hour, minute=sch.break_end.minute)
                if slot_time >= break_start and slot_time < break_end:
                    slot_time = break_end
                    continue
            # Location schedule window
            if loc_schedules:
                inside_any = False
                for lsch in loc_schedules:
                    l_start = date_obj.replace(hour=lsch.start_time.hour, minute=lsch.start_time.minute)
                    l_end = date_obj.replace(hour=lsch.end_time.hour, minute=lsch.end_time.minute)
                    if lsch.break_start and lsch.break_end:
                        lb_start = date_obj.replace(hour=lsch.break_start.hour, minute=lsch.break_start.minute)
                        lb_end = date_obj.replace(hour=lsch.break_end.hour, minute=lsch.break_end.minute)
                    else:
                        lb_start = lb_end = None
                    if slot_time >= l_start and (slot_time + timedelta(minutes=duration)) <= l_end:
                        if lb_start and lb_end and slot_time >= lb_start and slot_time < lb_end:
                            pass
                        else:
                            inside_any = True
                            break
                if not inside_any:
                    slot_time += timedelta(minutes=15)
                    continue
            livre = True
            slot_end = slot_time + timedelta(minutes=duration)
            for ag_start, ag_end in ocupados:
                if (slot_time < ag_end and slot_end > ag_start):
                    livre = False
                    break
            if livre:
                slots.append(slot_time.strftime("%H:%M"))
            slot_time += timedelta(minutes=15)
    if request.method == 'POST':
        session['agendamento'] = {
            'service_id': session.get('service_id'),
            'professional_id': session.get('professional_id'),
            'period': session.get('period'),
            'date': session.get('date'),
            'horario': request.form['horario']
        }
        return redirect(url_for('main.confirmar_agendamento', salao_slug=salao_slug))
    return render_template(
        'cliente_horario.html',
        slots=slots,
        salao_slug=salao_slug,
        back_url=url_for('main.salao_data', salao_slug=salao_slug)
    )

@main.route('/<salao_slug>/confirmar', methods=['GET', 'POST'])
def confirmar_agendamento(salao_slug):
    agendamento = session.get('agendamento')
    if not agendamento:
        return redirect(url_for('main.agendamento_sucesso', salao_slug=salao_slug))

    # Buscar objetos para exibir na tela de confirmação
    service = Service.query.get(agendamento['service_id'])
    professional = Professional.query.get(agendamento['professional_id'])
    data = agendamento['date']
    horario = agendamento['horario']

    if request.method == 'POST':
        # Aqui salva o agendamento no banco
        appointment = Appointment(
            service_id=service.id,
            professional_id=professional.id,
            appointment_time=datetime.strptime(f"{data} {horario}", "%Y-%m-%d %H:%M"),
            # Adapte para incluir o customer_id conforme seu fluxo de login
            customer_id=session.get('customer_id'),
            location_id=session.get('location_id')
        )
        db.session.add(appointment)
        db.session.commit()
        session.pop('agendamento', None)
        return redirect(url_for('main.agendamento_sucesso', salao_slug=salao_slug))

    return render_template(
        'confirmar_agendamento.html',
        service=service,
        professional=professional,
        data=data,
        horario=horario
    )

@main.route('/<salao_slug>/sucesso')
def agendamento_sucesso(salao_slug):
    return render_template('agendamento_sucesso.html', salao_slug=salao_slug)

@main.route('/<salao_slug>/meus_agendamentos', methods=['GET', 'POST'])
def meus_agendamentos_cliente(salao_slug):
    customer_id = session.get('customer_id')
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    if not customer_id:
        return redirect(url_for('main.customer_login', salao_slug=salao_slug))
    hoje = datetime.today()
    agendamentos = Appointment.query.join(Professional).filter(
        Appointment.customer_id == customer_id,
        Professional.admin_id == admin.id,
        Appointment.appointment_time >= hoje,
        Appointment.ativo == True  # Supondo que você tenha um campo "ativo" para soft delete
    ).order_by(Appointment.appointment_time.asc()).all()
    return render_template('meus_agendamentos_cliente.html', agendamentos=agendamentos, salao_slug=salao_slug)

@main.route('/<salao_slug>/cancelar_agendamento/<int:agendamento_id>', methods=['POST'])
def cancelar_agendamento_cliente(salao_slug, agendamento_id):
    customer_id = session.get('customer_id')
    agendamento = Appointment.query.get_or_404(agendamento_id)
    if agendamento.customer_id != customer_id:
        abort(403)
    agendamento.ativo = False  # Supondo que exista esse campo
    db.session.commit()
    flash('Agendamento cancelado com sucesso!', 'success')
    return redirect(url_for('main.meus_agendamentos_cliente', salao_slug=salao_slug))

@main.route('/dashboard/add_event', methods=['POST'])
@login_required
def dashboard_add_event():
    if current_user.role != 'admin':
        abort(403)
    profissional_id = request.form.get('profissional_id', type=int)
    descricao = request.form.get('descricao')
    data = request.form.get('data')
    hora = request.form.get('hora')
    duracao = request.form.get('duracao', type=int)
    tipo = request.form.get('tipo')  # 'agendamento' ou 'bloqueio'

    if not (profissional_id and descricao and data and hora and duracao):
        flash('Preencha todos os campos!', 'danger')
        return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))

    profissional = Professional.query.filter_by(id=profissional_id, admin_id=current_user.id).first_or_404()
    inicio = datetime.strptime(f"{data} {hora}", "%Y-%m-%d %H:%M")

    if tipo == 'bloqueio':
        if not _is_slot_available(profissional, inicio, duracao, current_user, location_id=None):
            flash('Horário indisponível para bloqueio.', 'danger')
            return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))
        bloqueio = Appointment(
            professional_id=profissional.id,
            service_id=None,
            customer_id=None,
            appointment_time=inicio,
            ativo=True
        )
        bloqueio.descricao = descricao
        bloqueio.duracao = duracao
        db.session.add(bloqueio)
        db.session.commit()
        flash('Bloqueio adicionado!', 'success')
    else:
        # Agendamento manual (pode ser adaptado para buscar cliente/serviço)
        flash('Agendamento manual não implementado neste MVP.', 'info')

    return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))


@main.route('/dashboard/create_appointment', methods=['POST'])
@login_required
def dashboard_create_appointment():
    if current_user.role != 'admin':
        abort(403)
    profissional_id = request.form.get('profissional_id', type=int)
    service_id = request.form.get('service_id', type=int)
    customer_id = request.form.get('customer_id', type=int)
    customer_name = (request.form.get('customer_name') or '').strip()
    customer_phone = (request.form.get('customer_phone') or '').strip()
    data = request.form.get('data')
    hora = request.form.get('hora')
    # No BASIC, exigir location_id
    location_id = request.form.get('location_id', type=int)
    require_location = is_basic(current_user)
    if not (profissional_id and service_id and customer_id and data and hora and ((not require_location) or location_id)):
        flash('Preencha todos os campos para o agendamento.', 'danger')
        return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))
    profissional = Professional.query.filter_by(id=profissional_id, admin_id=current_user.id).first_or_404()
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    customer = Customer.query.get_or_404(customer_id)
    inicio = datetime.strptime(f"{data} {hora}", "%Y-%m-%d %H:%M")
    # No BASIC, validar se o serviço é oferecido no local escolhido
    if require_location and location_id:
        service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
        if not any(l.id == int(location_id) for l in service.locations):
            flash('Este serviço não é oferecido no local selecionado.', 'danger')
            return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))

    # Cria cliente rápido se não selecionado da lista
    if not customer_id and customer_name:
        cust = Customer(name=customer_name, phone=customer_phone or None)
        db.session.add(cust)
        db.session.commit()
        if current_user not in cust.admins:
            cust.admins.append(current_user)
            db.session.commit()
        customer = cust
    else:
        customer = Customer.query.get_or_404(customer_id)

    # Valida disponibilidade do slot
    if not _is_slot_available(profissional, inicio, service.duration, current_user, location_id=(location_id if require_location else None)):
        flash('Horário indisponível para este serviço.', 'danger')
        return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))

    appointment = Appointment(
        professional_id=profissional.id,
        service_id=service.id,
        customer_id=customer.id,
        appointment_time=inicio,
        ativo=True,
        location_id=location_id if require_location else None
    )
    db.session.add(appointment)
    db.session.commit()
    flash('Agendamento criado com sucesso!', 'success')
    return redirect(url_for('main.dashboard', data=data, profissional_id=profissional_id))


@main.route('/dashboard/available_times', methods=['GET'])
@login_required
def dashboard_available_times():
    if current_user.role != 'admin':
        abort(403)
    profissional_id = request.args.get('profissional_id', type=int)
    service_id = request.args.get('service_id', type=int)
    date_str = request.args.get('date')
    if not (profissional_id and service_id and date_str):
        return jsonify({'ok': False, 'error': 'missing_parameters'}), 400
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first()
    profissional = Professional.query.filter_by(id=profissional_id, admin_id=current_user.id).first()
    if not (service and profissional):
        return jsonify({'ok': False, 'error': 'not_found'}), 404
    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
    weekday = date_obj.weekday()
    duration = service.duration
    schedules = ProfessionalSchedule.query.filter_by(professional_id=profissional.id, weekday=weekday).all()
    agendamentos = Appointment.query.filter(
        Appointment.professional_id == profissional.id,
        func.date(Appointment.appointment_time) == date_obj.date(),
        Appointment.ativo == True
    ).all()
    ocupados = []
    for ag in agendamentos:
        if ag.service_id:
            dur = Service.query.get(ag.service_id).duration
        else:
            dur = ag.duracao or 0
        ag_start = ag.appointment_time
        ag_end = ag_start + timedelta(minutes=dur)
        ocupados.append((ag_start, ag_end))

    # Plano BASIC: considerar janela de Local se informada
    loc_schedules = []
    if is_basic(current_user):
        loc_id = request.args.get('location_id', type=int)
        if loc_id:
            # validar que o serviço é oferecido no local
            if not any(l.id == int(loc_id) for l in service.locations):
                return jsonify({'ok': True, 'slots': []})
            loc_schedules = LocationSchedule.query.filter_by(location_id=loc_id, weekday=weekday).all()

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
        slot_time = date_obj.replace(hour=sch.start_time.hour, minute=sch.start_time.minute)
        end_time = date_obj.replace(hour=sch.end_time.hour, minute=sch.end_time.minute)
        while slot_time + timedelta(minutes=duration) <= end_time:
            # Pula intervalo de pausa
            if sch.break_start and sch.break_end:
                break_start = date_obj.replace(hour=sch.break_start.hour, minute=sch.break_start.minute)
                break_end = date_obj.replace(hour=sch.break_end.hour, minute=sch.break_end.minute)
                if slot_time >= break_start and slot_time < break_end:
                    slot_time = break_end
                    continue
            # Se há janela de local, garantir que o slot caia dentro dela
            if loc_schedules:
                inside_any = False
                for lsch in loc_schedules:
                    l_start = date_obj.replace(hour=lsch.start_time.hour, minute=lsch.start_time.minute)
                    l_end = date_obj.replace(hour=lsch.end_time.hour, minute=lsch.end_time.minute)
                    if lsch.break_start and lsch.break_end:
                        lb_start = date_obj.replace(hour=lsch.break_start.hour, minute=lsch.break_start.minute)
                        lb_end = date_obj.replace(hour=lsch.break_end.hour, minute=lsch.break_end.minute)
                    else:
                        lb_start = lb_end = None
                    if slot_time >= l_start and (slot_time + timedelta(minutes=duration)) <= l_end:
                        if lb_start and lb_end and slot_time >= lb_start and slot_time < lb_end:
                            pass
                        else:
                            inside_any = True
                            break
                if not inside_any:
                    slot_time += timedelta(minutes=15)
                    continue
            livre = True
            slot_end = slot_time + timedelta(minutes=duration)
            for ag_start, ag_end in ocupados:
                if (slot_time < ag_end and slot_end > ag_start):
                    livre = False
                    break
            if livre:
                slots.append(slot_time.strftime("%H:%M"))
            slot_time += timedelta(minutes=15)
    return jsonify({'ok': True, 'slots': slots})

@main.route('/api/customers/search')
@login_required
def api_search_customers():
    if current_user.role != 'admin':
        abort(403)
    q = (request.args.get('q') or '').strip()
    if not q:
        return jsonify({'ok': True, 'results': []})
    # Somente clientes que já tiveram agenda neste salão
    sub = db.session.query(Appointment.customer_id).join(Professional).filter(Professional.admin_id == current_user.id).distinct().subquery()
    customers = Customer.query.filter(Customer.id.in_(sub), Customer.name.ilike(f"%{q}%")).order_by(Customer.name.asc()).limit(10).all()
    return jsonify({'ok': True, 'results': [{'id': c.id, 'name': c.name, 'phone': c.phone} for c in customers]})

@main.route('/dashboard/cancelar/<int:agendamento_id>', methods=['POST'])
@login_required
def dashboard_cancelar_agendamento(agendamento_id):
    if current_user.role != 'admin':
        abort(403)
    agendamento = Appointment.query.get_or_404(agendamento_id)
    if agendamento.professional.admin_id != current_user.id:
        abort(403)
    agendamento.ativo = False
    db.session.commit()
    flash('Agendamento cancelado!', 'success')
    return redirect(request.referrer or url_for('main.dashboard'))

@main.route('/professionals')
@login_required
def professionals_list():
    if current_user.role != 'admin':
        abort(403)
    if is_basic(current_user):
        professionals = [ensure_default_professional(current_user)]
    else:
        professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    return render_template('professionals_list.html', back_url=url_for('main.dashboard'), professionals=professionals)

@main.route('/services')
@login_required
def services_list():
    if current_user.role != 'admin':
        abort(403)
    services = Service.query.filter_by(admin_id=current_user.id).all()
    professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    return render_template('services_list.html', services=services, professionals=professionals)

@main.route('/confirm_delete_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def confirm_delete_service(service_id):
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    if request.method == 'POST':
        # Exclui agendamentos desse serviço
        Appointment.query.filter_by(service_id=service.id).delete()
        db.session.delete(service)
        db.session.commit()
        flash('Serviço e todos os agendamentos excluídos!', 'success')
        return redirect(url_for('main.services_list'))
    return render_template('confirm_delete_service.html', service=service)


# ==========================
# Locations management
# ==========================

@main.route('/locations')
@login_required
def locations_list():
    if current_user.role != 'admin':
        abort(403)
    if not is_basic(current_user):
        flash('Seu plano não permite gerenciar Locais.', 'warning')
        return redirect(url_for('main.dashboard'))
    locations = Location.query.filter_by(admin_id=current_user.id).all()
    return render_template('locations_list.html', locations=locations)


@main.route('/add_location', methods=['GET','POST'])
@login_required
def add_location():
    if current_user.role != 'admin':
        abort(403)
    if not is_basic(current_user):
        flash('Seu plano não permite adicionar Locais.', 'warning')
        return redirect(url_for('main.dashboard'))
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            loc = Location(name=name, admin_id=current_user.id)
            db.session.add(loc)
            db.session.commit()
            workdays = request.form.getlist('workdays')
            for i in range(7):
                if str(i) in workdays:
                    start = request.form.get(f'start_{i}')
                    end = request.form.get(f'end_{i}')
                    break_start = request.form.get(f'break_start_{i}') or None
                    break_end = request.form.get(f'break_end_{i}') or None
                    if start and end:
                        sch = LocationSchedule(
                            location_id=loc.id,
                            weekday=i,
                            start_time=start,
                            end_time=end,
                            break_start=break_start,
                            break_end=break_end
                        )
                        db.session.add(sch)
            db.session.commit()
            flash('Local adicionado!', 'success')
            return redirect(url_for('main.locations_list'))
        flash('Nome é obrigatório.', 'danger')
    return render_template('add_location.html')


@main.route('/edit_location/<int:location_id>', methods=['GET','POST'])
@login_required
def edit_location(location_id):
    if current_user.role != 'admin':
        abort(403)
    if not is_basic(current_user):
        flash('Seu plano não permite editar Locais.', 'warning')
        return redirect(url_for('main.dashboard'))
    loc = Location.query.filter_by(id=location_id, admin_id=current_user.id).first_or_404()
    dias = ['Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sab', 'Dom']
    horarios = {sch.weekday: sch for sch in loc.schedules}
    if request.method == 'POST':
        name = request.form.get('name')
        if name:
            loc.name = name
            LocationSchedule.query.filter_by(location_id=loc.id).delete()
            db.session.commit()
            workdays = request.form.getlist('workdays')
            for i in range(7):
                if str(i) in workdays:
                    start = request.form.get(f'start_{i}')
                    end = request.form.get(f'end_{i}')
                    break_start = request.form.get(f'break_start_{i}') or None
                    break_end = request.form.get(f'break_end_{i}') or None
                    if start and end:
                        sch = LocationSchedule(
                            location_id=loc.id,
                            weekday=i,
                            start_time=start,
                            end_time=end,
                            break_start=break_start,
                            break_end=break_end
                        )
                        db.session.add(sch)
            db.session.commit()
            flash('Local atualizado!', 'success')
            return redirect(url_for('main.locations_list'))
        flash('Nome é obrigatório.', 'danger')
    return render_template('edit_location.html', location=loc, dias=dias, horarios=horarios)


# ==========================
# Admin profile
# ==========================

@main.route('/dashboard/profile', methods=['GET','POST'])
@login_required
def dashboard_profile():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        full_name = request.form.get('full_name')
        phone = request.form.get('phone')
        plan = (request.form.get('plan') or current_user.plan or 'free').lower()
        current_user.company_name = company_name or current_user.company_name
        current_user.full_name = full_name or current_user.full_name
        current_user.phone = phone or current_user.phone
        if plan in ('free','basic','pro'):
            current_user.plan = plan
            if is_basic(current_user):
                ensure_default_professional(current_user)
        # Photo
        file = request.files.get('profile_photo')
        if file and file.filename:
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            # salva como webp processado
            safe_name = f"user_{current_user.id}.webp"
            upload_dir = current_app.config.get('UPLOAD_FOLDER')
            os.makedirs(upload_dir, exist_ok=True)
            save_path = os.path.join(upload_dir, safe_name)
            try:
                from PIL import Image
                img = Image.open(file.stream).convert('RGB')
                w, h = img.size
                side = min(w, h)
                left = (w - side)//2
                top = (h - side)//2
                img = img.crop((left, top, left+side, top+side))
                img = img.resize((512, 512), Image.LANCZOS)
                img.save(save_path, 'WEBP', quality=90, method=6)
            except Exception:
                # fallback
                file.save(save_path)
            rel_path = os.path.relpath(save_path, os.path.join(current_app.root_path, 'static')).replace('\\','/')
            current_user.profile_photo = rel_path
        db.session.commit()
        flash('Perfil atualizado!', 'success')
        return redirect(url_for('main.dashboard_profile'))
    return render_template('dashboard_profile.html')