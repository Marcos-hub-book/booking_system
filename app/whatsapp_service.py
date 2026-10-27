import hashlib
import os
import re
import uuid
from datetime import datetime, timedelta

import requests
from flask import current_app, has_request_context, url_for

from . import db
from .models import Appointment, Customer, User, WhatsAppReminderQueue


def _utc_now():
    return datetime.utcnow()


def _normalize_whatsapp_number(raw):
    if raw is None:
        return None
    digits = re.sub(r'\D', '', str(raw).strip())
    if not digits:
        return None
    if digits.startswith('55'):
        return digits
    if digits.startswith('0') and len(digits) > 10:
        return '55' + digits[1:]
    if len(digits) == 11:
        return '55' + digits
    if len(digits) == 10:
        return '55' + digits
    return '55' + digits


def _build_public_url(endpoint_name, **values):
    try:
        if has_request_context():
            return url_for(endpoint_name, **values, _external=True)
    except Exception:
        pass

    base_url = (os.getenv('APP_BASE_URL') or '').rstrip('/')
    if base_url:
        return f"{base_url}/{values.get('salao_slug', '')}{values.get('path', '')}"
    return ''


def build_meus_agendamentos_url(admin):
    if not admin:
        return ''
    try:
        if has_request_context():
            return url_for('main.meus_agendamentos_cliente', salao_slug=admin.username, _external=True)
    except Exception:
        pass
    base_url = (os.getenv('APP_BASE_URL') or '').rstrip('/')
    if base_url:
        return f"{base_url}/{admin.username}/meus-agendamentos"
    return f"https://localhost/{admin.username}/meus-agendamentos"


def build_reagendar_url(admin):
    if not admin:
        return ''
    try:
        if has_request_context():
            return url_for('main.salao_home', salao_slug=admin.username, _external=True)
    except Exception:
        pass
    base_url = (os.getenv('APP_BASE_URL') or '').rstrip('/')
    if base_url:
        return f"{base_url}/{admin.username}"
    return f"https://localhost/{admin.username}"


def _message_payload(appointment, message_type):
    customer = appointment.customer
    admin = appointment.professional.admin if appointment.professional else None
    if not customer or not admin:
        return None

    service_name = appointment.service.name if appointment.service else 'serviço'
    date_label = appointment.appointment_time.strftime('%d/%m/%Y')
    time_label = appointment.appointment_time.strftime('%H:%M')

    if message_type == 'reminder_24h':
        link = build_meus_agendamentos_url(admin)
        text = (
            f"Olá {customer.name}, seu agendamento em {admin.company_name} é dia {date_label} às {time_label}. "
            f"Acesse seus agendamentos: {link}"
        )
        return {'text': text, 'link': link, 'service_name': service_name}

    if message_type == 'reminder_1h':
        link = build_meus_agendamentos_url(admin)
        text = (
            f"Olá {customer.name}, seu atendimento em {admin.company_name} começa em 1 hora ({date_label} às {time_label}). "
            f"Acesse seus agendamentos: {link}"
        )
        return {'text': text, 'link': link, 'service_name': service_name}

    if message_type == 'cancellation_professional':
        link = build_reagendar_url(admin)
        text = (
            f"Olá {customer.name}, seu agendamento em {admin.company_name} foi cancelado pelo profissional. "
            f"Para reagendar, acesse: {link}"
        )
        return {'text': text, 'link': link, 'service_name': service_name}

    return None


def _dedupe_key(appointment_id, message_type):
    return hashlib.sha256(f'{appointment_id}:{message_type}'.encode('utf-8')).hexdigest()


def _queue_message(appointment, message_type, scheduled_for):
    if not appointment or not appointment.customer:
        return None
    phone = _normalize_whatsapp_number(appointment.customer.phone)
    if not phone:
        return None
    if scheduled_for <= _utc_now():
        return None

    payload = _message_payload(appointment, message_type)
    if not payload:
        return None

    existing = WhatsAppReminderQueue.query.filter_by(dedupe_key=_dedupe_key(appointment.id, message_type)).first()
    if existing and existing.status in {'queued', 'processing', 'failed'}:
        return existing
    if existing and existing.status == 'sent':
        return existing

    queue_item = WhatsAppReminderQueue(
        admin_id=appointment.professional.admin_id,
        appointment_id=appointment.id,
        customer_id=appointment.customer_id,
        message_type=message_type,
        status='queued',
        scheduled_for=scheduled_for,
        dedupe_key=_dedupe_key(appointment.id, message_type),
        payload={
            'number': phone,
            'text': payload['text'],
            'link': payload['link'],
            'service_name': payload['service_name'],
            'message_type': message_type,
        },
        attempts=0,
        max_attempts=3,
    )
    db.session.add(queue_item)
    db.session.flush()
    return queue_item


def enqueue_whatsapp_reminders_for_appointment(appointment):
    if not appointment or not appointment.id:
        return []
    if not appointment.ativo:
        return []

    appointment_time = appointment.appointment_time
    queue_items = []

    reminder_24h = appointment_time - timedelta(hours=24)
    reminder_1h = appointment_time - timedelta(hours=1)

    item_24h = _queue_message(appointment, 'reminder_24h', reminder_24h)
    if item_24h:
        queue_items.append(item_24h)

    item_1h = _queue_message(appointment, 'reminder_1h', reminder_1h)
    if item_1h:
        queue_items.append(item_1h)

    return queue_items


def cancel_pending_whatsapp_reminders(appointment_id):
    if not appointment_id:
        return 0
    rows = WhatsAppReminderQueue.query.filter(
        WhatsAppReminderQueue.appointment_id == appointment_id,
        WhatsAppReminderQueue.status.in_(['queued', 'processing', 'failed'])
    ).all()
    for row in rows:
        row.status = 'cancelled'
        row.cancelled_at = _utc_now()
        row.locked_at = None
        row.lock_token = None
        row.updated_at = _utc_now()
    db.session.commit()
    return len(rows)


def _send_via_evolution(number, text):
    base_url = (os.getenv('EVOLUTION_URL') or '').rstrip('/')
    api_key = os.getenv('EVOLUTION_API_KEY') or ''
    instance = os.getenv('EVOLUTION_INSTANCE') or 'default'

    if not base_url or not api_key:
        raise RuntimeError('EVOLUTION_URL e EVOLUTION_API_KEY devem estar configurados.')

    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json',
    }

    candidate_payloads = [
        {'number': number, 'text': text, 'instanceName': instance},
        {'number': number, 'text': text, 'instance': instance},
        {'number': number, 'text': text},
    ]

    candidate_urls = [
        f'{base_url}/message/sendText',
        f'{base_url}/api/message/sendText',
        f'{base_url}/instance/{instance}/message/sendText',
    ]

    last_error = None
    for url in candidate_urls:
        for payload in candidate_payloads:
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                if response.status_code in (200, 201, 202):
                    data = response.json() if response.content else {}
                    if isinstance(data, dict):
                        return {'ok': True, 'response': data}
                    return {'ok': True, 'response': {'raw': data}}

                try:
                    last_error = response.json()
                except Exception:
                    last_error = {'status_code': response.status_code, 'text': response.text[:500]}
            except Exception as exc:
                last_error = {'exception': str(exc)}

    if last_error is None:
        last_error = {'error': 'unknown'}
    raise RuntimeError(f'Falha ao enviar WhatsApp pela Evolution: {last_error}')


def process_whatsapp_queue(limit=20):
    now = _utc_now()
    rows = WhatsAppReminderQueue.query.filter(
        WhatsAppReminderQueue.status.in_(['queued', 'failed']),
        WhatsAppReminderQueue.scheduled_for <= now
    ).order_by(WhatsAppReminderQueue.scheduled_for.asc()).limit(limit).all()

    processed = 0
    for row in rows:
        if row.status == 'cancelled':
            continue
        if row.lock_token and row.locked_at and row.locked_at > now - timedelta(minutes=5):
            continue

        row.status = 'processing'
        row.locked_at = now
        row.lock_token = uuid.uuid4().hex
        row.updated_at = now
        db.session.commit()

        try:
            if not row.customer or not row.customer.phone:
                row.status = 'cancelled'
                row.cancelled_at = now
                row.error_message = 'Cliente sem telefone cadastrado.'
                db.session.commit()
                continue

            payload = row.payload or {}
            number = payload.get('number') or _normalize_whatsapp_number(row.customer.phone)
            text = payload.get('text') or ''
            if not number or not text:
                row.status = 'failed'
                row.error_message = 'Payload inválido para envio.'
                db.session.commit()
                continue

            result = _send_via_evolution(number, text)
            row.status = 'sent'
            row.sent_at = now
            row.provider_message_id = str((result or {}).get('response', {}).get('key', '') or (result or {}).get('response', {}).get('id', '') or '')
            row.error_message = None
            row.locked_at = None
            row.lock_token = None
            row.updated_at = now
            db.session.commit()
            processed += 1
        except Exception as exc:
            row.attempts = (row.attempts or 0) + 1
            row.locked_at = None
            row.lock_token = None
            row.error_message = str(exc)
            row.status = 'failed' if row.attempts < (row.max_attempts or 3) else 'failed'
            row.updated_at = now
            db.session.commit()

    return processed


def schedule_cancelation_message(appointment):
    if not appointment or not appointment.customer:
        return None
    phone = _normalize_whatsapp_number(appointment.customer.phone)
    if not phone:
        return None

    payload = _message_payload(appointment, 'cancellation_professional')
    if not payload:
        return None

    existing = WhatsAppReminderQueue.query.filter_by(dedupe_key=_dedupe_key(appointment.id, 'cancellation_professional')).first()
    if existing:
        return existing

    item = WhatsAppReminderQueue(
        admin_id=appointment.professional.admin_id,
        appointment_id=appointment.id,
        customer_id=appointment.customer_id,
        message_type='cancellation_professional',
        status='queued',
        scheduled_for=_utc_now() + timedelta(minutes=1),
        dedupe_key=_dedupe_key(appointment.id, 'cancellation_professional'),
        payload={
            'number': phone,
            'text': payload['text'],
            'link': payload['link'],
            'service_name': payload['service_name'],
            'message_type': 'cancellation_professional',
        },
        attempts=0,
        max_attempts=3,
    )
    db.session.add(item)
    db.session.flush()
    return item
