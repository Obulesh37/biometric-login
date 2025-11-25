const express = require('express');
const cors = require('cors');
const cbor = require('cbor');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_ID = process.env.RP_ID || 'localhost';

app.use(cors({ origin: ORIGIN, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

const users = new Map();
const challenges = new Map();

const toBase64Url = buf => buf.toString('base64url');

app.post('/register/request', (req, res) => {
  const { email, name } = req.body;
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
    rp: { id: RP_ID, name: "Demo App" },
    user: { id: toBase64Url(Buffer.from(email)), name: email, displayName: name },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    authenticatorSelection: { userVerification: "preferred", residentKey: "preferred" },
    timeout: 60000
  });
});

app.post('/register/response', (req, res) => {
  const { sessionId, credential } = req.body;
  const session = challenges.get(sessionId);
  if (!session) return res.status(400).json({ error: 'Expired' });

  try {
    const clientData = JSON.parse(new TextDecoder().decode(credential.response.clientDataJSON));
    if (clientData.challenge !== session.challenge || clientData.origin !== ORIGIN)
      throw new Error('Invalid');

    const attestation = cbor.decodeFirstSync(credential.response.attestationObject);
    const authData = attestation.authData;
    const dataView = new DataView(authData.buffer, authData.byteOffset);
    const credIdLen = dataView.getUint16(53);
    const publicKey = cbor.decodeFirstSync(authData.slice(55 + credIdLen));

    users.set(credential.id, {
      name: session.name,
      email: session.email,
      credentialId: credential.id,
      credentialPublicKey: publicKey,
      counter: 0
    });

    challenges.delete(sessionId);
    res.json({ success: true });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post('/login/request', (req, res) => {
  const { email } = req.body;
  const user = [...users.values()].find(u => u.email === email.toLowerCase());
  if (!user) return res.status(404).json({ error: 'Not found' });

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

app.post('/login/response', (req, res) => {
  const { sessionId, assertion } = req.body;
  const session = challenges.get(sessionId);
  if (!session) return res.status(400).json({ error: 'Expired' });

  try {
    const clientData = JSON.parse(new TextDecoder().decode(assertion.response.clientDataJSON));
    if (clientData.challenge !== session.challenge || clientData.origin !== ORIGIN)
      throw new Error('Invalid');

    const user = users.get(assertion.id);
    if (!user) throw new Error('Not found');

    const authData = Buffer.from(assertion.response.authenticatorData);
    const clientDataHash = crypto.createHash('sha256').update(assertion.response.clientDataJSON).digest();
    const sig = Buffer.from(assertion.response.signature);

    const verify = crypto.createVerify('SHA256');
    verify.update(Buffer.concat([authData, clientDataHash]));
    if (!verify.verify(user.credentialPublicKey, sig))
      throw new Error('Bad signature');

    const counter = authData.readUInt32BE(33);
    if (counter <= user.counter) throw new Error('Replay');
    user.counter = counter;

    challenges.delete(sessionId);
    res.json({ success: true, user: { name: user.name, email: user.email } });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.get('/admin/users', (req, res) => {
  res.json({ total: users.size, users: [...users.values()].map(u => ({ name: u.name, email: u.email })) });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));

module.exports = app;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`LIVE → ${ORIGIN}`);
  console.log(`Admin → ${ORIGIN}/admin.html`);
});
