(function(){
  const $ = (sel) => document.querySelector(sel);
  const phoneInput = $('#phone-input');
  const btnStart = $('#btn-start');
  const screenLogin = $('#screen-login');
  const screenVerify = $('#screen-verify');
  const screenRegister = $('#screen-register');
  const phoneLabel = $('#phone-label');
  const codeInput = $('#code-input');
  const btnVerify = $('#btn-verify');
  const btnResend = $('#btn-resend');
  const msg = $('#msg');
  const firstName = $('#first-name');
  const lastName = $('#last-name');
  const email = $('#email');
  const birthdate = $('#birthdate');
  const phoneReadonly = $('#phone-readonly');
  const btnRegister = $('#btn-register');

  let confirmationResult = null;
  let idToken = null;
  let e164Phone = null; // +55XXXXXXXXXXX
  let resendTimer = null;
  let countdown = 30;

  function onlyDigits(s){ return (s || '').replace(/\D/g,''); }
  function maskPhone(digits){
    // Expect 11 digits (Brazil). Format: (XX) X XXXX-XXXX
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

  window.maskPhone = maskPhone; // expose if needed elsewhere

  function show(el){ el && (el.style.display = 'block'); }
  function hide(el){ el && (el.style.display = 'none'); }
  function setMsg(text, error=true){
    if(!msg) return;
    msg.style.display = text ? 'block' : 'none';
    msg.style.color = error ? '#b00020' : '#2e7d32';
    msg.textContent = text || '';
  }

  function startResendCountdown(){
    btnResend.disabled = true;
    countdown = 30;
    btnResend.textContent = `Reenviar código (${countdown})`;
    clearInterval(resendTimer);
    resendTimer = setInterval(() => {
      countdown -= 1;
      if(countdown <= 0){
        clearInterval(resendTimer);
        btnResend.disabled = false;
        btnResend.textContent = 'Reenviar código';
      } else {
        btnResend.textContent = `Reenviar código (${countdown})`;
      }
    }, 1000);
  }

  function ensureFirebase(){
    if(!window.firebase || !window.firebase.auth){
      setMsg('Firebase não carregado. Verifique sua configuração.', true);
      return false;
    }
    if(!window._firebaseInitialized){
      try {
        firebase.initializeApp(window.FIREBASE_CONFIG || {});
        window._firebaseInitialized = true;
      } catch(e) {
        // ignore if already initialized
        window._firebaseInitialized = true;
      }
    }
    return true;
  }

  function setupRecaptcha(){
    try{
      if(!window.recaptchaVerifier){
        window.recaptchaVerifier = new firebase.auth.RecaptchaVerifier('recaptcha-container', {
          size: 'invisible'
        });
      }
    }catch(e){
      console.error('recaptcha error', e);
    }
  }

  async function checkPhoneExists(e164){
    try{
      const res = await fetch('/api/auth/check_phone', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: e164, salao_slug: window.SALAO_SLUG })
      });
      return await res.json();
    }catch(err){
      return { ok:false, error:'network_error' };
    }
  }

  async function sendCode(){
    setMsg('');
    if(!ensureFirebase()) return;
    setupRecaptcha();
    try{
      confirmationResult = await firebase.auth().signInWithPhoneNumber(e164Phone, window.recaptchaVerifier);
      phoneLabel.textContent = e164Phone;
      hide(screenLogin);
      show(screenVerify);
      startResendCountdown();
    }catch(e){
      console.error(e);
      setMsg('Falha ao enviar SMS. Verifique o número e tente novamente.');
    }
  }

  async function verifyCode(){
    setMsg('');
    const code = onlyDigits(codeInput.value);
    if(code.length !== 6){ setMsg('Código inválido.'); return; }
    try{
      const cred = await confirmationResult.confirm(code);
      idToken = await cred.user.getIdToken();
      // Exchange on backend
      const res = await fetch('/api/auth/exchange', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ idToken, salao_slug: window.SALAO_SLUG })
      });
      const data = await res.json();
      if(!data.ok){ setMsg('Erro ao validar no servidor.'); return; }
      if(data.requiresRegistration){
        phoneReadonly.value = e164Phone;
        hide(screenVerify); show(screenRegister);
      } else {
        // Success -> go to scheduling options
        window.location.href = `/${window.SALAO_SLUG}/opcoes`;
      }
    }catch(e){
      console.error(e);
      setMsg('Código incorreto. Tente novamente.');
    }
  }

  async function registerCustomer(){
    setMsg('');
    if(!idToken){ setMsg('Sessão expirada. Volte e tente novamente.'); return; }
    const fn = (firstName.value || '').trim();
    const ln = (lastName.value || '').trim();
    const bd = (birthdate.value || '').trim();
    if(fn.length < 2){ setMsg('Informe seu nome.'); return; }
    if(!bd){ setMsg('Informe sua data de nascimento.'); return; }
    try{
      const res = await fetch('/api/auth/register', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ idToken, salao_slug: window.SALAO_SLUG, firstName: fn, lastName: ln, email: (email.value||'').trim(), birthdate: bd })
      });
      const data = await res.json();
      if(!data.ok){ setMsg('Erro ao salvar cadastro.'); return; }
      window.location.href = `/${window.SALAO_SLUG}/opcoes`;
    }catch(e){
      console.error(e);
      setMsg('Erro de rede ao salvar cadastro.');
    }
  }

  // Input masking
  phoneInput && phoneInput.addEventListener('input', () => {
    const digits = onlyDigits(phoneInput.value);
    phoneInput.value = maskPhone(digits);
  });

  btnStart && btnStart.addEventListener('click', async () => {
    const digits = onlyDigits(phoneInput.value);
    if(digits.length !== 11){ setMsg('Número inválido. Digite 11 dígitos.'); return; }
    // Brazil default +55
    e164Phone = `+55${digits}`;
    const chk = await checkPhoneExists(e164Phone);
    if(chk && chk.ok){
      if(chk.existsInLocal && chk.name){
        setMsg(`Olá, ${chk.name}! Parece que você já possui uma conta.`, false);
      }
    }
    await sendCode();
  });

  btnVerify && btnVerify.addEventListener('click', verifyCode);
  btnResend && btnResend.addEventListener('click', sendCode);
  btnRegister && btnRegister.addEventListener('click', registerCustomer);
})();
