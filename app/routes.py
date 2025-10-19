from flask import render_template, redirect, url_for, flash, request, Blueprint, abort, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from . import db, login_manager
from .models import User, Professional, Service, Appointment, Customer, ProfessionalSchedule
from datetime import datetime, timedelta
from sqlalchemy import func, or_
from .forms import LoginForm, RegistrationForm, AppointmentForm
from sqlalchemy.orm import joinedload

main = Blueprint('main', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@main.route('/')
def index():
    return render_template('index.html')

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
        flash('Conta criada com sucesso! Você pode agora fazer login.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if current_user.role != 'admin':
        abort(403)

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
        .options(joinedload(Appointment.professional), joinedload(Appointment.service), joinedload(Appointment.customer)) \
        .order_by(Appointment.appointment_time.asc()) \
        .all()

    # Para mostrar horários vagos, pegue todos os serviços para saber as durações
    servicos = Service.query.filter_by(admin_id=current_user.id).all()

    # Navegação de datas
    prev_date = (data - timedelta(days=1)).strftime("%Y-%m-%d")
    next_date = (data + timedelta(days=1)).strftime("%Y-%m-%d")

    return render_template(
        'dashboard_agenda.html',
        profissionais=profissionais,
        profissional_id=profissional_id,
        agendamentos=agendamentos,
        servicos=servicos,
        data=data,
        prev_date=prev_date,
        next_date=next_date,
        status=status
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
    return render_template('add_professional.html')

@main.route('/add_service', methods=['GET', 'POST'])
@login_required
def add_service():
    if current_user.role != 'admin':
        abort(403)
    professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = request.form.get('name')
        duration = request.form.get('duration')
        price = request.form.get('price')
        professional_ids = request.form.getlist('professional_ids')
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
            db.session.add(new_service)
            db.session.commit()
            flash('Service added successfully!', 'success')
            return redirect(url_for('main.dashboard'))
    return render_template('add_service.html', professionals=professionals)

@main.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.filter_by(id=service_id, admin_id=current_user.id).first_or_404()
    professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    if request.method == 'POST':
        name = request.form.get('name')
        duration = request.form.get('duration', type=int)
        price = request.form.get('price', type=float)
        professional_ids = request.form.getlist('professional_ids')
        if name and duration and price is not None:
            service.name = name
            service.duration = duration
            service.price = price
            # Atualiza profissionais
            service.professionals = [Professional.query.get(int(pid)) for pid in professional_ids]
            db.session.commit()
            flash('Serviço atualizado com sucesso!', 'success')
            return redirect(url_for('main.services_list'))
        flash('Preencha todos os campos.', 'danger')
    selected_ids = [str(p.id) for p in service.professionals]
    return render_template('edit_service.html', service=service, professionals=professionals, selected_ids=selected_ids)

@main.route('/delete_service/<int:id>')
@login_required
def delete_service(id):
    return f"Delete Service {id} - Em construção"

@main.route('/edit_professional/<int:professional_id>', methods=['GET', 'POST'])
@login_required
def edit_professional(professional_id):
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
    return render_template('cliente_opcoes.html', salao_slug=salao_slug)

@main.route('/<salao_slug>/servico', methods=['GET', 'POST'])
def salao_servico(salao_slug):
    admin = User.query.filter_by(username=salao_slug, role='admin').first_or_404()
    services = Service.query.filter_by(admin_id=admin.id).all()
    if request.method == 'POST':
        service_id = request.form.get('service_id')
        session['service_id'] = service_id
        return redirect(url_for('main.salao_profissional', salao_slug=salao_slug))
    return render_template(
        'cliente_servico.html',
        services=services,
        salao_slug=salao_slug,
        back_url=url_for('main.customer_login', salao_slug=salao_slug)
    )

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

    # Se não trabalha nesse dia, retorna False
    if not schedules:
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
            customer_id=session.get('customer_id')
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
        # Cria um "agendamento" sem cliente/serviço, só bloqueio
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
    professionals = Professional.query.filter_by(admin_id=current_user.id).all()
    return render_template('professionals_list.html', professionals=professionals)

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