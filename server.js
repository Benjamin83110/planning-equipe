/**
 * Planning Équipe — Serveur temps réel avec authentification
 * WebSocket pur Node.js natif (http + crypto + fs)
 * Aucune dépendance externe requise
 */
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const crypto= require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// ─── MOT DE PASSE ─────────────────────────────────────────────────────────────
// Changez cette valeur pour définir votre mot de passe
const PASSWORD = process.env.PASSWORD || 'planning2024';

// Sessions valides (token → expiration)
const sessions = new Map();

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isValidToken(token) {
  if (!token || !sessions.has(token)) return false;
  const exp = sessions.get(token);
  if (Date.now() > exp) { sessions.delete(token); return false; }
  return true;
}

function getTokenFromCookie(cookieHeader) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(/token=([a-f0-9]+)/);
  return match ? match[1] : null;
}

// ─── Persistance JSON ─────────────────────────────────────────────────────────
let state = {
  members: [], absences: {}, blocks: [], vAssign: {},
  taskTitles: {}, diItems: [], medItems: [], comItems: [],
  nextIds: { mId: 1, tId: 1, bId: 1, dId: 1, medId: 1, comId: 1 }
};

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      console.log('✅ Données chargées depuis data.json');
    } else {
      const DEF = ['Nathalie','Benjamin','Bernard','Sébastien','Jean-Rémy','Juliette',
                   'Aurore','Anne-Marie','Florent','Jean-Baptiste','Valérie','Patricia','Saline'];
      state.members = DEF.map((name, i) => ({ id: i + 1, name }))
                         .sort((a, b) => a.name.localeCompare(b.name, 'fr'));
      state.nextIds.mId = DEF.length + 1;
      saveData();
      console.log('✅ État initial créé avec les membres par défaut');
    }
  } catch (e) { console.error('❌ Erreur chargement:', e.message); }
}

let saveTimer = null;
function saveData() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2)); } catch (e) {}
  }, 500);
}

// ─── Page de connexion ────────────────────────────────────────────────────────
const LOGIN_PAGE = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Planning Équipe — Connexion</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#F7F8FA;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border:1px solid #E2E6EA;border-radius:16px;padding:40px;width:340px;box-shadow:0 4px 24px rgba(0,0,0,.08);text-align:center}
.logo{width:52px;height:52px;background:#185FA5;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;margin:0 auto 20px}
h1{font-size:20px;font-weight:700;color:#1A2332;margin-bottom:6px}
p{font-size:13px;color:#8A97A8;margin-bottom:28px}
input{width:100%;font-size:14px;padding:11px 14px;border:1px solid #CBD2DA;border-radius:8px;outline:none;margin-bottom:14px;transition:border-color .15s}
input:focus{border-color:#185FA5}
button{width:100%;font-size:14px;font-weight:600;padding:11px;border:none;border-radius:8px;background:#185FA5;color:#fff;cursor:pointer;transition:background .15s}
button:hover{background:#0C447C}
.err{font-size:13px;color:#E24B4A;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">📋</div>
  <h1>Planning Équipe</h1>
  <p>Saisissez le mot de passe pour accéder au planning</p>
  <form method="POST" action="/login">
    <input type="password" name="password" placeholder="Mot de passe" autofocus required/>
    <button type="submit">Accéder au planning</button>
  </form>
  ERREUR_PLACEHOLDER
</div>
</body>
</html>`;

// ─── WebSocket ────────────────────────────────────────────────────────────────
const clients = new Map(); // socket → token

function wsHandshake(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
}

function wsDecodeFrame(buf) {
  if (buf.length < 2) return null;
  const masked = !!(buf[1] & 0x80);
  let len = buf[1] & 0x7f, offset = 2;
  if (len === 126) { len = buf.readUInt16BE(2); offset = 4; }
  else if (len === 127) { len = Number(buf.readBigUInt64BE(2)); offset = 10; }
  if (buf.length < offset + (masked ? 4 : 0) + len) return null;
  let payload;
  if (masked) {
    const mask = buf.slice(offset, offset + 4); offset += 4;
    payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = buf[offset + i] ^ mask[i % 4];
  } else { payload = buf.slice(offset, offset + len); }
  return payload.toString('utf8');
}

function wsEncodeFrame(msg) {
  const payload = Buffer.from(msg, 'utf8');
  const len = payload.length;
  let frame;
  if (len < 126) {
    frame = Buffer.alloc(2 + len); frame[0] = 0x81; frame[1] = len; payload.copy(frame, 2);
  } else if (len < 65536) {
    frame = Buffer.alloc(4 + len); frame[0] = 0x81; frame[1] = 126;
    frame.writeUInt16BE(len, 2); payload.copy(frame, 4);
  } else {
    frame = Buffer.alloc(10 + len); frame[0] = 0x81; frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(len), 2); payload.copy(frame, 10);
  }
  return frame;
}

function broadcast(msg, sender = null) {
  const frame = wsEncodeFrame(msg);
  for (const [s] of clients) {
    if (s !== sender && s.writable) { try { s.write(frame); } catch {} }
  }
}

function sendTo(socket, msg) {
  if (socket.writable) { try { socket.write(wsEncodeFrame(msg)); } catch {} }
}

// ─── Serveur HTTP ─────────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      const params = {};
      body.split('&').forEach(p => {
        const [k, v] = p.split('=');
        if (k) params[decodeURIComponent(k)] = decodeURIComponent((v||'').replace(/\+/g,' '));
      });
      resolve(params);
    });
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');

  // ── POST /login ──
  if (req.method === 'POST' && req.url === '/login') {
    const body = await parseBody(req);
    if (body.password === PASSWORD) {
      const token = generateToken();
      const exp = Date.now() + 8 * 60 * 60 * 1000; // 8h
      sessions.set(token, exp);
      res.writeHead(302, {
        'Set-Cookie': `token=${token}; HttpOnly; Path=/; Max-Age=28800`,
        'Location': '/'
      });
      res.end();
    } else {
      const page = LOGIN_PAGE.replace('ERREUR_PLACEHOLDER',
        '<p style="color:#E24B4A;margin-top:12px;font-size:13px">Mot de passe incorrect</p>');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(page);
    }
    return;
  }

  // ── GET /logout ──
  if (req.url === '/logout') {
    const token = getTokenFromCookie(req.headers.cookie);
    if (token) sessions.delete(token);
    res.writeHead(302, {
      'Set-Cookie': 'token=; HttpOnly; Path=/; Max-Age=0',
      'Location': '/login'
    });
    res.end();
    return;
  }

  // ── GET /login ──
  if (req.url === '/login') {
    const page = LOGIN_PAGE.replace('ERREUR_PLACEHOLDER', '');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(page);
    return;
  }

  // ── Vérification token pour toutes les autres routes ──
  const token = getTokenFromCookie(req.headers.cookie);
  if (!isValidToken(token)) {
    res.writeHead(302, { 'Location': '/login' });
    res.end();
    return;
  }

  // ── GET / → planning ──
  if (req.url === '/' || req.url === '/index.html') {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    try {
      const html = fs.readFileSync(htmlPath);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch {
      res.writeHead(404); res.end('index.html introuvable');
    }
    return;
  }

  if (req.url === '/api/state') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(state));
    return;
  }

  res.writeHead(404); res.end('Not found');
});

// ─── WebSocket upgrade ────────────────────────────────────────────────────────
server.on('upgrade', (req, socket) => {
  if (req.url !== '/ws') { socket.destroy(); return; }

  // Vérifier le token dans le cookie
  const token = getTokenFromCookie(req.headers.cookie);
  if (!isValidToken(token)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    socket.destroy(); return;
  }

  wsHandshake(req, socket);
  clients.set(socket, token);
  console.log(`🔌 Client connecté (${clients.size} total)`);

  let buf = Buffer.alloc(0);
  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    const text = wsDecodeFrame(buf);
    if (text !== null) {
      buf = Buffer.alloc(0);
      let msg;
      try { msg = JSON.parse(text); } catch { return; }
      if (msg.type === 'GET_STATE') {
        sendTo(socket, JSON.stringify({ type: 'STATE', data: state }));
      } else if (msg.type === 'UPDATE') {
        state = msg.data; saveData();
        broadcast(JSON.stringify({ type: 'STATE', data: state }), socket);
      }
    }
  });

  socket.on('close', () => { clients.delete(socket); console.log(`🔌 Client déconnecté (${clients.size} restant)`); });
  socket.on('error', () => clients.delete(socket));
});

// ─── Démarrage ────────────────────────────────────────────────────────────────
loadData();
server.listen(PORT, () => {
  console.log(`\n🚀 Planning Équipe démarré sur le port ${PORT}`);
  console.log(`   Mot de passe : ${PASSWORD}`);
  console.log(`   (Changez-le avec la variable d'environnement PASSWORD)\n`);
});
