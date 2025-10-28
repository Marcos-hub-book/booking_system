(function(){
  const $ = (sel) => document.querySelector(sel);
  const phoneInput = $('#phone-input');
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
  const birthdate = $('#birthdate');
  const phoneReadonly = $('#phone-readonly');
  const passReg = $('#password-register');
  const passReg2 = $('#password-register-2');
  const btnRegister = $('#btn-register');

  let rawDigits = '';
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
  window.maskPhone = maskPhone;

  function setMsg(text, error=true){
    if(!msg) return;
    msg.style.display = text ? 'block' : 'none';
    msg.style.color = error ? '#b00020' : '#2e7d32';
    msg.textContent = text || '';
  }
  function show(el){ if(el) el.style.display='block'; }
  function hide(el){ if(el) el.style.display='none'; }

  async function checkPhone(){
    try{
      const res = await fetch('/api/auth/check_phone', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ phone: phoneNormalized, salao_slug: window.SALAO_SLUG })
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
        body: JSON.stringify({ phone: phoneNormalized, password: pwd, salao_slug: window.SALAO_SLUG })
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
    const bd = (birthdate.value||'').trim();
    const pw1 = (passReg.value||'').trim();
    const pw2 = (passReg2.value||'').trim();
    if(fn.length < 2){ setMsg('Informe seu nome.'); return; }
    if(!bd){ setMsg('Informe sua data de nascimento.'); return; }
    if(pw1.length < 4){ setMsg('Senha muito curta (mín. 4).'); return; }
    if(pw1 !== pw2){ setMsg('As senhas não conferem.'); return; }
    try{
      const res = await fetch('/api/auth/register', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ salao_slug: window.SALAO_SLUG, firstName: fn, lastName: ln, email: (email.value||'').trim(), birthdate: bd, phone: phoneNormalized, password: pw1 })
      });
      const data = await res.json();
      if(!data.ok){ setMsg('Erro ao salvar cadastro.'); return; }
      window.location.href = `/${window.SALAO_SLUG}/opcoes`;
    }catch(e){ setMsg('Erro de rede ao salvar cadastro.'); }
  }

  phoneInput && phoneInput.addEventListener('input', () => {
    rawDigits = onlyDigits(phoneInput.value);
    phoneInput.value = maskPhone(rawDigits);
  });

  btnStart && btnStart.addEventListener('click', async () => {
    if(rawDigits.length !== 11){ setMsg('Número inválido. Digite 11 dígitos.'); return; }
    // Normalizamos para formato local sem +55, pois backend usa conforme salvo
    phoneNormalized = rawDigits; // ex: 11987654321
    const chk = await checkPhone();
    if(!chk || !chk.ok){ setMsg('Erro ao verificar telefone.'); return; }
    if(chk.exists){
      customerName.textContent = chk.name || 'Cliente';
      hide(screenLogin); show(screenPassword);
    } else {
      phoneReadonly.value = maskPhone(rawDigits);
      hide(screenLogin); show(screenRegister);
    }
  });

  btnLogin && btnLogin.addEventListener('click', doLogin);
  btnRegister && btnRegister.addEventListener('click', doRegister);
  btnBack1 && btnBack1.addEventListener('click', () => { hide(screenPassword); show(screenLogin); });
  btnBack2 && btnBack2.addEventListener('click', () => { hide(screenRegister); show(screenLogin); });
})();
