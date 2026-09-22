'use strict';

const tls = require('tls');
const os = require('os');
const fs = require('fs');
const h2 = require('http2');
const UltraWS = require('turbo-ws');

const CONFIG_FILE = __dirname + '/config.json';
if (!fs.existsSync(CONFIG_FILE)) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify({ token: '', guildid: '' }, null, 2) + '\n');
}
const CFG = require(CONFIG_FILE);
const TOKEN = CFG.token || '';
const GUILD_ID = CFG.guildid || '';
if (!TOKEN || !GUILD_ID) {
  process.stdout.write('[config] ' + CONFIG_FILE + ' created — fill in token and guildid, then run again\n');
  process.exit(1);
}

try { os.setPriority(process.pid, -20); } catch {}
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const HOSTS = ['canary.discord.com', 'canary.discordapp.com', 'ptb.discord.com', 'discord.com', 'discordapp.com'];
const PORTS = [8443, 443];
const UA = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) discordcanary/1.0.9225 Chrome/138.0.7204.251 Electron/37.6.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.251 Safari/537.36',
];
const XSP = 'eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6NTc5MDczfQ==';
const MFA_FILE = __dirname + '/mfa.txt';
const GATEWAYS = [
  'wss://gateway.discord.gg/?v=9&encoding=json',
  'wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json',
  'wss://gateway-eu-west1-b.discord.gg/?v=9&encoding=json',
];
const HB_INTERVAL = 41250;
const H2_SETTINGS = Object.freeze({ enablePush: false, headerTableSize: 4096, maxConcurrentStreams: 100, initialWindowSize: 65535, maxFrameSize: 16384, maxHeaderListSize: 8192 });
const KEEPALIVE_REQ = Buffer.from('GET / HTTP/1.1\r\nHost: canary.discord.com\r\n\r\n');
const H2_PING_REQ = Object.freeze({ ':method': 'HEAD', ':path': '/api/v9/gateway' });
const idle = () => {};

const guilds = new Map();
const patches = new Map();
const rawSockets = [];
const h2Sessions = [];
let mfaToken = null;

function tlsSock(host, port, alpn) {
  const s = tls.connect({ host, port, servername: host, rejectUnauthorized: false, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: alpn, keepAlive: true, handshakeTimeout: 500 });
  s.setNoDelay(true);
  s.setKeepAlive(true, 5000);
  return s;
}

function buildRawSocket(i) {
  const host = HOSTS[i % HOSTS.length];
  const port = PORTS[i < HOSTS.length ? 0 : 1];
  const s = tlsSock(host, port, ['http/1.1']);
  s.on('error', idle);
  s.on('end', idle);
  s.on('data', idle);
  s.on('close', () => { s.removeAllListeners(); queueMicrotask(() => { rawSockets[i] = buildRawSocket(i); }); });
  return s;
}

function buildH2Session(i) {
  const s = h2.connect('https://canary.discord.com', { createConnection: () => tlsSock('canary.discord.com', 443, ['h2']), settings: H2_SETTINGS });
  s.on('error', idle);
  s.on('goaway', idle);
  s.on('close', () => { s.removeAllListeners(); queueMicrotask(() => { h2Sessions[i] = buildH2Session(i); }); });
  return s;
}

for (let i = 0; i < HOSTS.length * PORTS.length; i++) rawSockets[i] = buildRawSocket(i);
for (let i = 0; i < 5; i++) h2Sessions[i] = buildH2Session(i);

function buildPatch(vanityCode) {
  const body = '{"code":"' + vanityCode + '"}';
  const mfaHdr = mfaToken ? '\r\nX-Discord-MFA-Authorization: ' + mfaToken : '';
  const raw = [];
  for (let i = 0; i < rawSockets.length; i++) {
    raw[i] = Buffer.from('PATCH /api/v9/guilds/' + GUILD_ID + '/vanity-url HTTP/1.1\r\nHost: ' + HOSTS[i % HOSTS.length] + '\r\nAuthorization: ' + TOKEN + mfaHdr + '\r\nContent-Type: application/json\r\nUser-Agent: ' + UA[i % UA.length] + '\r\nX-Super-Properties: ' + XSP + '\r\nContent-Length: ' + body.length + '\r\n\r\n' + body);
  }
  const h2Headers = Object.freeze({
    ':method': 'PATCH',
    ':path': '/api/v9/guilds/' + GUILD_ID + '/vanity-url',
    'authorization': TOKEN,
    'content-type': 'application/json',
    'user-agent': UA[0],
    'x-super-properties': XSP,
    ...(mfaToken ? { 'x-discord-mfa-authorization': mfaToken } : {}),
  });
  return { raw, h2Headers, body: Buffer.from(body), vanityCode };
}

function syncPatches() { for (const [id, vc] of guilds) patches.set(id, buildPatch(vc)); }

function firePatch({ raw, h2Headers, body }) {
  for (let i = 0; i < rawSockets.length; i++) {
    const s = rawSockets[i];
    if (s && s.writable && !s.destroyed) s.write(raw[i]);
  }
  for (const s of h2Sessions) {
    if (s && !s.destroyed) { const st = s.request(h2Headers); st.on('error', idle); st.end(body); }
  }
}

function readField(raw, off) { const e = raw.indexOf('"', off); return e < 0 ? null : raw.toString('utf8', off, e); }
function readGuildId(raw) { const di = raw.indexOf('"d":'); if (di < 0) return null; const ii = raw.indexOf('"id":"', di); return ii < 0 ? null : readField(raw, ii + 6); }
function readVanity(raw) { const vi = raw.indexOf('"vanity_url_code":"'); return vi < 0 ? null : readField(raw, vi + 19); }

function onMessage(si, raw) {
  if (!raw || !raw.length) return;
  if (raw.indexOf('"GUILD_UPDATE"') >= 0) {
    if (raw.indexOf('"vanity_url_code"') < 0) return;
    if (raw.indexOf('"vanity_url_code":null') >= 0 || raw.indexOf('"vanity_url_code": null') >= 0) {
      const id = readGuildId(raw);
      const r = id && patches.get(id);
      if (r) firePatch(r);
    } else {
      const id = readGuildId(raw);
      if (id) {
        const nv = readVanity(raw);
        if (nv) { guilds.set(id, nv); patches.set(id, buildPatch(nv)); }
      }
    }
    return;
  }
  if (raw.indexOf('"READY"') >= 0) {
    guilds.clear();
    patches.clear();
    for (const g of JSON.parse(raw.toString('utf8')).d.guilds) {
      if (g.vanity_url_code) { guilds.set(g.id, g.vanity_url_code); patches.set(g.id, buildPatch(g.vanity_url_code)); }
    }
    process.stdout.write('[gw:' + si + '] ready x=' + guilds.size + ' ' + [...guilds.values()].join(',') + '\n');
  }
}

function openGateway(si, url) {
  const ws = new UltraWS(url, { origin: 'https://canary.discord.com', handshakeTimeout: 500, raw: true });
  let hbTimer = null;
  ws.onopen = () => {
    setTimeout(() => ws.send(UltraWS.discord.identify(TOKEN, { intents: 1 })), 100);
    hbTimer = setInterval(() => { if (ws.readyState === 1) ws.send(UltraWS.discord.heartbeat(null)); }, HB_INTERVAL);
  };
  ws.onmessage = (ev) => onMessage(si, ev.data);
  ws.onclose = () => { if (hbTimer) clearInterval(hbTimer); setTimeout(() => openGateway(si, url), 5000); };
  ws.onerror = idle;
  return ws;
}

function readMfa() {
  try {
    const t = fs.readFileSync(MFA_FILE, 'utf8').trim();
    if (t && t !== mfaToken) {
      mfaToken = t;
      syncPatches();
      process.stdout.write('[mfa] mfa.txt tok=' + t.length + '\n');
    }
  } catch {}
}
readMfa();
try { fs.watch(MFA_FILE, { persistent: true }, readMfa); } catch {}

rawSockets[0].once('secureConnect', () => {
  process.stdout.write('[net] up\n');
  GATEWAYS.forEach((url, i) => setTimeout(() => openGateway(i + 1, url), i * 5000));
  setInterval(() => { for (const s of rawSockets) if (s && (s.destroyed || (!s.writable && !s.connecting))) s.destroy(); }, 2000);
  setInterval(() => { for (const s of rawSockets) if (s && s.writable && !s.destroyed) s.write(KEEPALIVE_REQ); }, 5000);
  setInterval(() => { for (const s of h2Sessions) if (s && !s.destroyed) s.request(H2_PING_REQ, { endStream: true }).end(); }, 30000);
  setInterval(() => { for (const s of h2Sessions) if (s && !s.destroyed) s.ping(idle); }, 4000);
});

setTimeout(() => { process.stdout.write('[net] rst\n'); process.exit(0); }, 3600000);
process.stdout.write('[app] ok\n');
