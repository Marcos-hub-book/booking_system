(function(){
  const $ = (sel) => document.querySelector(sel);
  const identifierInput = $('#identifier-input');
  const btnStart = $('#btn-start');
  const screenLogin = $('#screen-login');
  const screenPassword = $('#screen-password');
  const screenRegister = $('#screen-register');
  const customerName = $('#customer-name');
  const passwordInput = $('#password-input');
  const btnLogin = $('#btn-login');
  const btnBack1 = $('#btn-back-1');
  const btnBack2 = $('#btn-back-2');
  const msg = $('#msg');

  const firstName = $('#first-name');
  const lastName = $('#last-name');
  const email = $('#email');
  const phoneRegInput = $('#phone-input-reg');
  const passReg = $('#password-register');
  const passReg2 = $('#password-register-2');
  const btnRegister = $('#btn-register');

  let identifierValue = '';
  let isPhoneIdentifier = false;
  let phoneNormalized = '';

  function onlyDigits(s){ return (s || '').replace(/\D/g,''); }
  function maskPhone(digits){
    const p = (digits || '').substring(0,11);
    const a = p.substring(0,2);
    const b = p.substring(2,3);
    const c = p.substring(3,7);
    const d = p.substring(7,11);
    if(p.length <= 2) return `(${a}`;
    if(p.length <= 3) return `(${a}) ${b}`;
    if(p.length <= 7) return `(${a}) ${b} ${c}`;
    return `(${a}) ${b} ${c}-${d}`;
  }

  function setMsg(text, error=true){
    if(!msg) return;
    msg.style.display = text ? 'block' : 'none';
    msg.style.color = error ? '#b00020' : '#2e7d32';
    msg.textContent = text || '';
  }
  function show(el){ if(el) el.style.display='block'; }
  function hide(el){ if(el) el.style.display='none'; }

  function isEmail(value){
    return value && value.includes('@') && value.includes('.') && !value.includes(' ');
  }

  async function checkIdentifier(){
    try{
      const res = await fetch('/api/auth/check_identifier', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ identifier: identifierValue, salao_slug: window.SALAO_SLUG })
      });
      return await res.json();
    }catch(e){ return { ok:false, error:'network' }; }
  }

  async function doLogin(){
    setMsg('');
    const pwd = (passwordInput.value||'').trim();
    if(pwd.length < 4){ setMsg('Senha inválida.'); return; }
    try{
      const res = await fetch('/api/auth/login', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ identifier: identifierValue, password: pwd, salao_slug: window.SALAO_SLUG })
      });
      const data = await res.json();
      if(!data.ok){ setMsg('Credenciais inválidas.'); return; }
      window.location.href = `/${window.SALAO_SLUG}/opcoes`;
    }catch(e){ setMsg('Erro de rede.'); }
  }

  async function doRegister(){
    setMsg('');
    const fn = (firstName.value||'').trim();
    const ln = (lastName.value||'').trim();
    const emailValue = (email.value||'').trim();
    const pw1 = (passReg.value||'').trim();
    const pw2 = (passReg2.value||'').trim();
    if(fn.length < 2){ setMsg('Informe seu nome.'); return; }
    if(!emailValue || !isEmail(emailValue)){ setMsg('Informe um email válido.'); return; }
    // Ensure phone is provided and normalized
    if(!phoneNormalized){
      const phoneRaw = (phoneRegInput && phoneRegInput.value) ? onlyDigits(phoneRegInput.value) : '';
      if(phoneRaw.length !== 11){ setMsg('Informe um telefone válido com 11 dígitos.'); return; }
      phoneNormalized = phoneRaw;
    }
    if(pw1.length < 6){ setMsg('Senha muito curta (mín. 6).'); return; }
    if(pw1 !== pw2){ setMsg('As senhas não conferem.'); return; }
    try{
      const res = await fetch('/api/auth/register', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({
          salao_slug: window.SALAO_SLUG,
          identifier: identifierValue,
          phone: phoneNormalized,
          firstName: fn,
          lastName: ln,
          email: emailValue,
          password: pw1
        })
      });
      const data = await res.json();
      if(!data.ok){
        if(data.error === 'email_taken'){
          setMsg('Este email já está cadastrado. Use "Esqueci minha senha" para recuperar a conta.');
        } else if(data.error === 'phone_taken'){
          setMsg('Este telefone já está cadastrado. Use "Esqueci minha senha" para recuperar a conta.');
        } else {
          setMsg('Erro ao salvar cadastro.');
        }
        return;
      }
      window.location.href = `/${window.SALAO_SLUG}/opcoes`;
    }catch(e){ setMsg('Erro de rede ao salvar cadastro.'); }
  }

  identifierInput && identifierInput.addEventListener('input', () => {
    identifierValue = (identifierInput.value||'').trim();
    if(isEmail(identifierValue)){
      isPhoneIdentifier = false;
      phoneNormalized = '';
      identifierInput.type = 'email';
    } else {
      isPhoneIdentifier = true;
      const digits = onlyDigits(identifierValue);
      identifierValue = digits;
      phoneNormalized = digits;
      identifierInput.value = maskPhone(digits);
      if(digits.length <= 11){ identifierInput.type = 'tel'; }
    }
  });

  btnStart && btnStart.addEventListener('click', async () => {
    identifierValue = (identifierInput.value||'').trim();
    if(!identifierValue){ setMsg('Digite telefone ou email.'); return; }
    if(isEmail(identifierValue)){
      isPhoneIdentifier = false;
    } else {
      const digits = onlyDigits(identifierValue);
      if(digits.length !== 11){ setMsg('Digite um telefone válido com 11 dígitos.'); return; }
      identifierValue = digits;
      isPhoneIdentifier = true;
      phoneNormalized = digits;
      identifierInput.value = maskPhone(digits);
    }
    const chk = await checkIdentifier();
    if(!chk || !chk.ok){ setMsg('Erro ao verificar usuário.'); return; }
    if(chk.exists){
      customerName.textContent = chk.name || 'Cliente';
      hide(screenLogin); show(screenPassword);
    } else {
      email.value = isPhoneIdentifier ? '' : identifierValue;
      if(phoneRegInput){
        phoneRegInput.value = isPhoneIdentifier ? maskPhone(phoneNormalized) : '';
      }
      hide(screenLogin); show(screenRegister);
    }
  });

  btnLogin && btnLogin.addEventListener('click', doLogin);
  btnRegister && btnRegister.addEventListener('click', doRegister);
  btnBack1 && btnBack1.addEventListener('click', () => { hide(screenPassword); show(screenLogin); });
  btnBack2 && btnBack2.addEventListener('click', () => { hide(screenRegister); show(screenLogin); });
})();
