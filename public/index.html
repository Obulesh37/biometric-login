<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Fingerprint Login</title>
  <style>
    body { font-family: system-ui; background: linear-gradient(135deg, #667eea, #764ba2); min-height: 100vh; margin:0; display:flex; align-items:center; justify-content:center; }
    .card { background:white; padding:40px; border-radius:20px; box-shadow:0 20px 50px rgba(0,0,0,0.3); width:90%; max-width:400px; text-align:center; }
    input, button { width:100%; padding:14px; margin:10px 0; border-radius:12px; border:1px solid #ddd; font-size:16px; }
    button { background:#667eea; color:white; border:none; cursor:pointer; }
    .status { padding:12px; border-radius:12px; margin:15px 0; font-weight:bold; }
    .success { background:#d4edda; color:#155724; }
    .error { background:#f8d7da; color:#721c24; }
    .hidden { display:none; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Fingerprint Login</h1>

    <div id="welcome" class="hidden">
      <h2>Welcome, <span id="name" style="color:#667eea"></span>!</h2>
      <p id="email"></p>
      <button onclick="location.reload()">Logout</button>
    </div>

    <div id="register">
      <input type="text" id="regName" placeholder="Name">
      <input type="email" id="regEmail" placeholder="Email">
      <button onclick="register()">Register with Fingerprint</button>
    </div>

    <div id="login" class="hidden">
      <input type="email" id="loginEmail" placeholder="Email">
      <button onclick="login()">Login with Fingerprint</button>
    </div>

    <div id="status" class="status success">Ready</div>
  </div>

  <script>
    const API = '';
    const status = document.getElementById('status');

    function setStatus(m, err=false) {
      status.textContent = m;
      status.className = err ? 'status error' : 'status success';
    }

    function fromBase64Url(b64) {
      const padding = '==='.slice(0, (4 - b64.length % 4) % 4);
      const base64 = (b64 + padding).replace(/-/g, '+').replace(/_/g, '/');
      return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    }

    async function register() {
      const name = document.getElementById('regName').value.trim();
      const email = document.getElementById('regEmail').value.trim();
      if (!name || !email) return setStatus('Fill all', true);

      setStatus('Touch sensor...');
      const res = await fetch(`${API}/register/request`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({name,email}) });
      const opts = await res.json();

      opts.challenge = fromBase64Url(opts.challenge);
      opts.user.id = fromBase64Url(opts.user.id);

      const cred = await navigator.credentials.create({ publicKey: opts });
      await fetch(`${API}/register/response`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({sessionId: opts.sessionId, credential: cred}) });

      setStatus('Registered! Now login');
      document.getElementById('login').classList.remove('hidden');
      document.getElementById('register').classList.add('hidden');
      document.getElementById('loginEmail').value = email;
    }

    async function login() {
      const email = document.getElementById('loginEmail').value.trim();
      if (!email) return setStatus('Enter email', true);

      setStatus('Touch sensor...');
      const res = await fetch(`${API}/login/request`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({email}) });
      const opts = await res.json();

      opts.challenge = fromBase64Url(opts.challenge);
      opts.allowCredentials.forEach(c => c.id = fromBase64Url(c.id));

      const assertion = await navigator.credentials.get({ publicKey: opts });
      const result = await fetch(`${API}/login/response`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({sessionId: opts.sessionId, assertion}) });
      const data = await result.json();

      if (data.success) {
        document.getElementById('name').textContent = data.user.name;
        document.getElementById('email').textContent = data.user.email;
        document.getElementById('welcome').classList.remove('hidden');
        document.getElementById('login').classList.add('hidden');
        setStatus('Success!');
      } else setStatus(data.error, true);
    }
  </script>
</body>
</html>
