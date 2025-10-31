# Booking System

This is an online scheduling system designed for beauty salons, clinics, and small businesses. It provides functionalities for managing appointments, professionals, and services through a user-friendly interface.

## Features

- User authentication for clients and administrators
- Scheduling appointments with professionals
- Management of services offered by professionals
- Responsive design suitable for mobile devices
- Admin dashboard for managing users and appointments

## Project Structure

```
booking_system
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── forms.py
│   ├── static
│   │   ├── css
│   │   │   └── styles.css
│   │   └── js
│   │       └── scripts.js
│   └── templates
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── schedule.html
│       └── admin.html
├── migrations
│   └── README.md
├── config.py
# Booking System

Sistema de agendamento online para salões, clínicas e pequenos negócios. Agora com autenticação de clientes por telefone + senha (sem SMS), mantendo sessão por 6 meses via cookie seguro.

## Novidades (Autenticação cliente)

- Login de cliente usando TELEFONE + SENHA (sem Firebase/SMS).
- Cadastro do cliente cria a senha, que é salva (hash) na base.
- Sessão persistente por 6 meses via cookie JWT (HttpOnly).
- Saudação “Olá, [Nome]” no canto superior esquerdo; clique para fazer logout.
- Se já estiver autenticado, ao acessar o link do salão pula o login e vai direto para as opções.

### Telas/Fluxo
1) `/<salao_slug>` — Home do salão. Botão “Entrar para agendar”.
2) `/<salao_slug>/entrar` — Fluxo do cliente:
   - Digita telefone (com máscara). Click “Continuar”.
   - Se telefone já cadastrado no salão → pedir senha e autenticar.
   - Se novo → formulário de cadastro (Nome, Sobrenome, Email opcional, Nascimento, Telefone pré-preenchido, Senha e Confirmar senha).
   - Após login/cadastro → cookie (6 meses) e redireciona para `/<salao_slug>/opcoes`.

## Estrutura do projeto

```
booking_system
├── app
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── forms.py
│   ├── static
│   │   ├── css
│   │   │   └── styles.css
│   │   └── js
│   │       ├── scripts.js
│   │       └── auth_password.js
│   └── templates
│       ├── base.html
│       ├── index.html
│       ├── login.html
│       ├── register.html
│       ├── dashboard.html
│       ├── schedule.html
│       ├── salao_home.html
│       └── cliente_login_phone.html  # Tela de telefone/senha/cadastro
├── migrations
│   ├── versions
│   │   └── a1b2c3d4e5f6_add_customer_password_email.py
│   └── ...
├── config.py
├── requirements.txt
└── README.md
```

## Instalação (Windows PowerShell)

1) Clonar e entrar na pasta
```powershell
git clone <repository-url>
cd booking_system
```

2) Ambiente virtual
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3) Dependências
```powershell
pip install -r requirements.txt
```

4) Variáveis de ambiente necessárias (desenvolvimento)
```powershell
$env:CPF_ENCRYPTION_KEY = "<chave_fernet_base64>"   # gere com Python: from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())
$env:CPF_HASH_SALT = "minha_salt_forte"
# Mercado Pago (será usado na integração de assinaturas)
$env:MERCADO_PAGO_ACCESS_TOKEN = "<seu_access_token>"
```

5) Configurar banco de dados
- Ajuste a URI no `config.py`.
- Rodar migrações (se ainda não inicializado o Alembic, faça apenas uma vez o init):
```powershell
$env:FLASK_APP = "app"
flask db upgrade
```

Se der erro dizendo que não existe pasta de migrações inicial, rode:
```powershell
flask db init
flask db migrate -m "init"
flask db upgrade
```

## Rodando a aplicação
```powershell
$env:FLASK_APP = "app"
flask run
```
Abra http://127.0.0.1:5000.

## Como usar (cliente)
1) Acesse `/<salao_slug>` e clique em “Entrar para agendar”.
2) Na tela seguinte, digite seu telefone e clique “Continuar”.
3) Se já tiver conta, informe a senha e entre. Se não, preencha o cadastro criando uma senha.
4) Ao logar/cadastrar, a sessão fica salva por 6 meses (cookie). Você verá “Olá, [Nome]”. Clique para sair (logout).

## Segurança
- A senha do cliente é armazenada com hash (Werkzeug).
- O cookie contém um JWT assinado no servidor, com expiração de 6 meses.
- Em produção, configure o cookie como `secure=True` (HTTPS) em `app/routes.py`.

## Observações
- Este projeto não usa mais Firebase nem autenticação por SMS.
- O telefone é armazenado sem DDI por padrão (11 dígitos Brasil). Adapte a máscara/normalização em `app/static/js/auth_password.js` se necessário.

## Licença
MIT

## Planos, Trial e Cobrança

- Página de planos: `/planos` (após cadastro)
- Trial: 30 dias grátis (uma vez por CPF). Inicia via botão “Teste grátis por 30 dias”.
- Billing: `/billing` exibe status; `/billing/expired` bloqueia acesso quando expira.
- Menu Dashboard → “Plano e cobrança”.

Campos criados no usuário (admin):
- cpf_encrypted (criptografado com Fernet) e cpf_hash (SHA-256 + salt)
- plan (free/basic/pro/advanced)
- subscription_status (trial/active/canceled/expired)
- trial_started_at, trial_ends_at, trial_consumed
- subscription_provider, subscription_id, current_period_end_at, canceled_at

Integração Mercado Pago (em progresso):
- Endpoint `/subscriptions/create` (stub) e webhook `/webhooks/mercadopago` (stub).
- Usaremos Preapproval (assinaturas) com idempotência e verificação de webhook.

Gates por plano:
- Basic: 1 profissional (padrão), Locais ilimitados.
- Pro: até 2 profissionais.
- Avançado: até 5 profissionais.

## Planos (Free, Basic, Pro)

- Free (padrão):
   - Até 1 profissional; não permite Locais.
   - Fluxo do cliente sem seleção de Local.

- Basic (multi-locais):
   - Não permite adicionar/editar/remover profissionais manualmente.
   - O sistema cria um profissional padrão com o nome da empresa.
   - Permite gerenciar Locais e horários dos Locais.
   - Fluxo do cliente pede Local antes do serviço quando houver Locais.
   - Disponibilidade considera a janela do Local (e, se existir, também a agenda do profissional padrão).

- Pro (multi-profissionais):
   - Permite múltiplos profissionais, serviços por profissional.
   - Não permite Locais (fluxo padrão por profissional).

Para alterar o plano: Dashboard → Meu perfil → campo “Plano”.

## Foto do salão (qualidade e formato)

- A foto é exibida sempre circular (CSS com `border-radius: 50%`).
- Ao atualizar pelo perfil, a imagem é processada: corte central quadrado, redimensionada para 512×512 e salva em WebP qualidade 90 (rápida e bonita).