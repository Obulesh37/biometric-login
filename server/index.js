const express = require('express');
const cors = require('cors');
const cbor = require('cbor');
const crypto = require('crypto');
const path = require('path');

const app = express();

// === CONFIG - IMPORTANT FOR DEPLOY ===
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_ID = process.env.RP_ID || 'localhost';
// ======================================

app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

// In-memory storage (lost on restart - perfect for demo)
const users = new Map();        // credentialId → user
const challenges = new Map();   // sessionId → temp data

// Helper
const toBase64Url = (buf) => buf.toString('base64url');

// Register Request
app.post('/register/request', (req, res) => {
  const { email, name } = req.body;
  if (!email || !name) return res.status(400).json({ error: 'Missing info' });

  const challenge = crypto.randomBytes(32);
  const sessionId = crypto.randomBytes(16).toString('hex');

  challenges.set(sessionId, {
    challenge: toBase64Url(challenge),
    email: email.toLowerCase(),
    name
  });

  res.json({
    sessionId,
    challenge: toBase64Url(challenge),
    rp: { id: RP_ID, name: "Biometric App" },
    user: {
      id: toBase64Url(Buffer.from(email)),
      name: email,
      displayName: name
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    timeout: 60000
  });
});

// Register Response
app.post('/register/response', (req, res) => {
  const { sessionId, credential } = req.body;
  const session = challenges.get(sessionId);
  if (!session) return res.status(400).json({ error: 'Session expired' });

  try {
    const clientData = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    if (clientData.challenge !== session.challenge || clientData.origin !== ORIGIN) {
      throw new Error('Invalid origin or challenge');
    }

    const attestation = cbor.decodeFirstSync(credential.response.attestationObject);
    const authData = attestation.authData;
    const dataView = new DataView(authData.buffer, authData.byteOffset);
    const credIdLen = dataView.getUint16(53);
    const publicKey = cbor.decodeFirstSync(authData.slice(55 + credIdLen));
    const credIdB64 = credential.id;

    users.set(credIdB64, {
      name: session.name,
      email: session.email,
      credentialId: credIdB64,
      credentialPublicKey: publicKey,
      counter: 0,
      registeredAt: new Date().toISOString()
    });

    challenges.delete(sessionId);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login Request
app.post('/login/request', (req, res) => {
  const { email } = req.body;
  const user = [...users.values()].find(u => u.email === email.toLowerCase());
  if (!user) return res.status(404).json({ error: 'No account found' });

  const challenge = toBase64Url(crypto.randomBytes(32));
  const sessionId = crypto.randomBytes(16).toString('hex');
  challenges.set(sessionId, { challenge, email: user.email });

  res.json({
    sessionId,
    challenge,
    allowCredentials: [{ type: "public-key", id: user.credentialId }],
    userVerification: "preferred"
  });
});

// Login Response
app.post('/login/response', (req, res) => {
  const { sessionId, assertion } = req.body;
  const session = challenges.get(sessionId);
  if (!session) return res.status(400).json({ error: 'Session expired' });

  try {
    const clientData = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
    if (clientData.challenge !== session.challenge || clientData.origin !== ORIGIN) {
      throw new Error('Invalid request');
    }

    const user = users.get(assertion.id);
    if (!user) throw new Error('Credential not found');

    const authData = Buffer.from(assertion.response.authenticatorData);
    const clientDataHash = crypto.createHash('sha256').update(assertion.response.clientDataJSON).digest();
    const signature = Buffer.from(assertion.response.signature);

    const verify = crypto.createVerify('SHA256');
    verify.update(Buffer.concat([authData, clientDataHash]));
    verify.end();

    if (!verify.verify(user.credentialPublicKey, signature)) {
      throw new Error('Invalid signature');
    }

    const counter = authData.readUInt32BE(33);
    if (counter <= user.counter) throw new Error('Replay attack');
    user.counter = counter;

    challenges.delete(sessionId);
    res.json({ success: true, user: { name: user.name, email: user.email } });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ADMIN: See all users
app.get('/admin/users', (req, res) => {
  const list = [...users.values()].map(u => ({
    name: u.name,
    email: u.email,
    registeredAt: u.registeredAt
  }));
  res.json({ total: list.length, users: list });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

module.exports = app;

if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`\nBiometric Login LIVE!`);
    console.log(`App: ${ORIGIN}`);
    console.log(`Admin Panel: ${ORIGIN}/admin.html\n`);
  });
}
