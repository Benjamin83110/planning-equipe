/**
 * Planning Équipe — Serveur temps réel
 * WebSocket pur Node.js natif (http + crypto + net)
 * Aucune dépendance externe requise
 */
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const crypto= require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// ─── Persistance JSON ────────────────────────────────────────────────────────
let state = {
  members: [],
  absences: {},
  blocks: [],
  vAssign: {},
  taskTitles: {},
  diItems: [],
  medItems: [],
  comItems: [],
  nextIds: { mId: 1, tId: 1, bId: 1, dId: 1, medId: 1, comId: 1 }
};

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      state = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      console.log('✅ Données chargées depuis data.json');
    } else {
      // Membres par défaut
      const DEF = ['Nathalie','Benjamin','Bernard','Sébastien','Jean-Rémy','Juliette',
                   'Aurore','Anne-Marie','Florent','Jean-Baptiste','Valérie','Patricia','Saline'];
      state.members = DEF.map((name, i) => ({ id: i + 1, name }))
                         .sort((a, b) => a.name.localeCompare(b.name, 'fr'));
      state.nextIds.mId = DEF.length + 1;
      saveData();
      console.log('✅ État initial créé avec les membres par défaut');
    }
  } catch (e) {
    console.error('❌ Erreur chargement données:', e.message);
  }
}

let saveTimer = null;
function saveData() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      fs.writeFileSync(DATA_FILE, JSON.stringify(state, null, 2));
    } catch (e) {
      console.error('❌ Erreur sauvegarde:', e.message);
    }
  }, 500);
}

// ─── Gestion WebSocket (RFC 6455 implémenté manuellement) ────────────────────
const clients = new Set();

function wsHandshake(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
}

function wsDecodeFrame(buf) {
  if (buf.length < 2) return null;
  const masked  = !!(buf[1] & 0x80);
  let len       = buf[1] & 0x7f;
  let offset    = 2;

  if (len === 126) { len = buf.readUInt16BE(2); offset = 4; }
  else if (len === 127) { len = Number(buf.readBigUInt64BE(2)); offset = 10; }

  if (buf.length < offset + (masked ? 4 : 0) + len) return null;

  let payload;
  if (masked) {
    const mask = buf.slice(offset, offset + 4);
    offset += 4;
    payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = buf[offset + i] ^ mask[i % 4];
  } else {
    payload = buf.slice(offset, offset + len);
  }
  return payload.toString('utf8');
}

function wsEncodeFrame(msg) {
  const payload = Buffer.from(msg, 'utf8');
  const len     = payload.length;
  let frame;

  if (len < 126) {
    frame = Buffer.alloc(2 + len);
    frame[0] = 0x81; frame[1] = len;
    payload.copy(frame, 2);
  } else if (len < 65536) {
    frame = Buffer.alloc(4 + len);
    frame[0] = 0x81; frame[1] = 126;
    frame.writeUInt16BE(len, 2);
    payload.copy(frame, 4);
  } else {
    frame = Buffer.alloc(10 + len);
    frame[0] = 0x81; frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
    payload.copy(frame, 10);
  }
  return frame;
}

function broadcast(msg, sender = null) {
  const frame = wsEncodeFrame(msg);
  for (const s of clients) {
    if (s !== sender && s.writable) {
      try { s.write(frame); } catch {}
    }
  }
}

function sendTo(socket, msg) {
  if (socket.writable) {
    try { socket.write(wsEncodeFrame(msg)); } catch {}
  }
}

function handleWsMessage(socket, raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch { return; }

  switch (msg.type) {
    case 'GET_STATE':
      // Le client demande l'état complet au moment de la connexion
      sendTo(socket, JSON.stringify({ type: 'STATE', data: state }));
      break;

    case 'UPDATE':
      // Le client envoie son état complet après chaque modification
      state = msg.data;
      saveData();
      // Propager à tous les autres clients
      broadcast(JSON.stringify({ type: 'STATE', data: state }), socket);
      break;

    default:
      console.warn('Message inconnu:', msg.type);
  }
}

// ─── Serveur HTTP ─────────────────────────────────────────────────────────────
const server = http.createServer((req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');

  if (req.url === '/' || req.url === '/index.html') {
    const htmlPath = path.join(__dirname, 'public', 'index.html');
    try {
      const html = fs.readFileSync(htmlPath);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch {
      res.writeHead(404);
      res.end('Fichier index.html introuvable dans /public/');
    }
    return;
  }

  // API REST : récupérer l'état (pour debug)
  if (req.url === '/api/state') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(state));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

// Upgrade HTTP → WebSocket
server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') { socket.destroy(); return; }
  if (req.headers.upgrade?.toLowerCase() !== 'websocket') { socket.destroy(); return; }

  wsHandshake(req, socket);
  clients.add(socket);
  console.log(`🔌 Client connecté (${clients.size} total)`);

  let buf = Buffer.alloc(0);
  socket.on('data', chunk => {
    buf = Buffer.concat([buf, chunk]);
    const text = wsDecodeFrame(buf);
    if (text !== null) {
      buf = Buffer.alloc(0);
      handleWsMessage(socket, text);
    }
  });

  socket.on('close', () => {
    clients.delete(socket);
    console.log(`🔌 Client déconnecté (${clients.size} restant)`);
  });

  socket.on('error', () => clients.delete(socket));
});

// ─── Démarrage ────────────────────────────────────────────────────────────────
loadData();
server.listen(PORT, () => {
  console.log(`\n🚀 Planning Équipe — Serveur démarré`);
  console.log(`   → Local :   http://localhost:${PORT}`);
  console.log(`   → Réseau :  http://[IP_DU_SERVEUR]:${PORT}`);
  console.log(`   → WebSocket: ws://[IP]:${PORT}/ws`);
  console.log(`\n   Données sauvegardées dans : ${DATA_FILE}`);
  console.log(`   ${clients.size} client(s) connecté(s)\n`);
});
