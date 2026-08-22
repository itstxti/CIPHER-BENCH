/* =========================================================
   CIPHERBENCH — client-side crypto toolkit
   Symmetric + asymmetric primitives via window.crypto.subtle.
   Argon2id via hash-wasm (loaded from CDN, used only in-browser).
   No network calls for data. No storage. No server component.
   ========================================================= */

// ---------- Hero cipher-strip animation ----------
(function heroCipher() {
  const el = document.getElementById('cipherText');
  const phrase = 'ENCRYPT LOCALLY. TRUST NOTHING ELSE.';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*<>/\\?';
  let frame = 0;
  const total = 36;
  function render() {
    let out = '';
    const revealCount = Math.floor((frame / total) * phrase.length);
    for (let i = 0; i < phrase.length; i++) {
      if (phrase[i] === ' ') { out += ' '; continue; }
      out += (i < revealCount) ? phrase[i] : chars[Math.floor(Math.random() * chars.length)];
    }
    el.textContent = out;
    frame++;
    if (frame <= total) requestAnimationFrame(() => setTimeout(render, 45));
  }
  render();
})();

// ---------- Tab switching ----------
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    ['text', 'file', 'asym', 'hash'].forEach(name => {
      document.getElementById('panel-' + name).style.display = (name === tab.dataset.tab) ? '' : 'none';
    });
  });
});

function wireModeSwitch(group, onChange) {
  const btns = document.querySelectorAll(`.mode-btn[data-group="${group}"]`);
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      btns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      onChange(btn.dataset.mode);
    });
  });
}

function setStatus(elId, state, label) {
  const el = document.getElementById(elId);
  el.className = 'status-light' + (state ? ' ' + state : '');
  el.innerHTML = '<span class="led"></span>' + label;
}
function showMsg(elId, text, type) {
  const el = document.getElementById(elId);
  el.textContent = text;
  el.className = 'msg show ' + type;
}
function hideMsg(elId) { document.getElementById(elId).className = 'msg'; }

function wirePwToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  btn.addEventListener('click', () => {
    const isPw = input.type === 'password';
    input.type = isPw ? 'text' : 'password';
    btn.textContent = isPw ? 'HIDE' : 'SHOW';
  });
}
wirePwToggle('textPwToggle', 'textPassword');
wirePwToggle('filePwToggle', 'filePassword');

document.getElementById('textPassword').addEventListener('input', (e) => {
  const v = e.target.value;
  let score = 0;
  if (v.length >= 8) score++;
  if (v.length >= 14) score++;
  if (/[A-Z]/.test(v) && /[a-z]/.test(v)) score++;
  if (/[0-9]/.test(v) && /[^A-Za-z0-9]/.test(v)) score++;
  document.querySelectorAll('#textStrength i').forEach((b, i) => {
    b.className = (i < score) ? (score <= 1 ? 'on-weak' : score <= 2 ? 'on-mid' : 'on-strong') : '';
  });
});

// =========================================================
// Byte / base64 / PEM helpers
// =========================================================
function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  return btoa(binary);
}
function base64ToBytes(b64) {
  const binary = atob(b64.trim());
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
function formatBytes(n) {
  if (n < 1024) return n + ' B';
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
  if (n < 1024 * 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  return (n / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}
function toPem(base64, label) {
  const lines = base64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}
function fromPem(pem) {
  return pem.replace(/-----BEGIN [^-]+-----/, '').replace(/-----END [^-]+-----/, '').replace(/\s+/g, '');
}
function downloadBytes(bytes, filename) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
function downloadText(text, filename) {
  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =========================================================
// Symmetric core (AES-256-GCM, PBKDF2 or Argon2id KDF)
// Packet layout: "CBS1" | kdfId(1) | salt(16) | iv(12) | ciphertext+tag
// =========================================================
const SALT_LEN = 16, IV_LEN = 12;
const SYM_MAGIC = new TextEncoder().encode('CBS1');
const PBKDF2_ITERATIONS = 250000;
const ARGON2_PARAMS = { parallelism: 1, iterations: 2, memorySize: 19456, hashLength: 32 }; // ~19 MiB, OWASP minimum profile

async function deriveKeyPBKDF2(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function deriveKeyArgon2id(password, salt) {
  if (typeof hashwasm === 'undefined') throw new Error('ARGON2_UNAVAILABLE');
  const keyBytes = await hashwasm.argon2id({
    password, salt,
    parallelism: ARGON2_PARAMS.parallelism,
    iterations: ARGON2_PARAMS.iterations,
    memorySize: ARGON2_PARAMS.memorySize,
    hashLength: ARGON2_PARAMS.hashLength,
    outputType: 'binary'
  });
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function deriveKeyKDF(password, salt, kdfId) {
  if (kdfId === 0) return deriveKeyPBKDF2(password, salt);
  if (kdfId === 1) return deriveKeyArgon2id(password, salt);
  throw new Error('FORMAT');
}

function packSym(kdfId, salt, iv, cipherBytes) {
  const out = new Uint8Array(4 + 1 + SALT_LEN + IV_LEN + cipherBytes.length);
  out.set(SYM_MAGIC, 0);
  out[4] = kdfId;
  out.set(salt, 5);
  out.set(iv, 5 + SALT_LEN);
  out.set(cipherBytes, 5 + SALT_LEN + IV_LEN);
  return out;
}
function unpackSym(bytes) {
  if (bytes.length < 5 + SALT_LEN + IV_LEN + 1) throw new Error('FORMAT');
  for (let i = 0; i < 4; i++) if (bytes[i] !== SYM_MAGIC[i]) throw new Error('FORMAT');
  const kdfId = bytes[4];
  const salt = bytes.slice(5, 5 + SALT_LEN);
  const iv = bytes.slice(5 + SALT_LEN, 5 + SALT_LEN + IV_LEN);
  const cipher = bytes.slice(5 + SALT_LEN + IV_LEN);
  return { kdfId, salt, iv, cipher };
}
async function encryptBytes(password, plainBytes, kdfId) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await deriveKeyKDF(password, salt, kdfId);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plainBytes);
  return packSym(kdfId, salt, iv, new Uint8Array(cipherBuf));
}
async function decryptBytes(password, packedBytes) {
  const { kdfId, salt, iv, cipher } = unpackSym(packedBytes);
  const key = await deriveKeyKDF(password, salt, kdfId);
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
    return new Uint8Array(plainBuf);
  } catch (e) {
    if (e.message === 'ARGON2_UNAVAILABLE') throw e;
    throw new Error('AUTH'); // wrong password OR corrupted/tampered data — GCM can't distinguish
  }
}

// =========================================================
// TEXT PANEL
// =========================================================
let textMode = 'encrypt';
wireModeSwitch('text', (mode) => {
  textMode = mode;
  document.getElementById('textInputLabel').textContent = mode === 'encrypt' ? 'Plaintext' : 'Ciphertext (base64)';
  document.getElementById('textInput').placeholder = mode === 'encrypt'
    ? 'Type or paste text here...' : 'Paste the base64 ciphertext produced by this tool...';
  document.getElementById('textKdfField').style.display = mode === 'encrypt' ? '' : 'none';
  document.getElementById('textOutputWrap').style.display = 'none';
  hideMsg('textMsg');
});

document.getElementById('textRun').addEventListener('click', async () => {
  const password = document.getElementById('textPassword').value;
  const input = document.getElementById('textInput').value;
  hideMsg('textMsg');
  if (!password) { showMsg('textMsg', 'Enter a password first.', 'err'); return; }
  if (!input) { showMsg('textMsg', 'Enter some text first.', 'err'); return; }

  setStatus('textStatus', '', 'WORKING…');
  const runBtn = document.getElementById('textRun');
  runBtn.disabled = true;
  try {
    if (textMode === 'encrypt') {
      const kdfId = parseInt(document.getElementById('textKdf').value, 10);
      const plainBytes = new TextEncoder().encode(input);
      const packed = await encryptBytes(password, plainBytes, kdfId);
      document.getElementById('textOutputLabel').textContent = 'Ciphertext (base64)';
      document.getElementById('textOutput').value = bytesToBase64(packed);
      document.getElementById('textOutputWrap').style.display = '';
      setStatus('textStatus', 'ready', 'ENCRYPTED');
    } else {
      let packed;
      try { packed = base64ToBytes(input); } catch (e) { throw new Error('FORMAT'); }
      const plainBytes = await decryptBytes(password, packed);
      document.getElementById('textOutputLabel').textContent = 'Plaintext';
      document.getElementById('textOutput').value = new TextDecoder().decode(plainBytes);
      document.getElementById('textOutputWrap').style.display = '';
      setStatus('textStatus', 'ready', 'DECRYPTED');
    }
  } catch (err) {
    setStatus('textStatus', 'error', 'FAILED');
    document.getElementById('textOutputWrap').style.display = 'none';
    if (err.message === 'AUTH') showMsg('textMsg', 'Decryption failed — wrong password, or the ciphertext is corrupted/tampered with.', 'err');
    else if (err.message === 'FORMAT') showMsg('textMsg', "That doesn't look like valid ciphertext from this tool (bad base64 or too short).", 'err');
    else if (err.message === 'ARGON2_UNAVAILABLE') showMsg('textMsg', 'Argon2id needs its WASM module from the CDN — check your connection, or re-encrypt using PBKDF2.', 'warn');
    else showMsg('textMsg', 'Unexpected error: ' + err.message, 'err');
  } finally { runBtn.disabled = false; }
});

document.getElementById('textClear').addEventListener('click', () => {
  document.getElementById('textPassword').value = '';
  document.getElementById('textInput').value = '';
  document.getElementById('textOutput').value = '';
  document.getElementById('textOutputWrap').style.display = 'none';
  hideMsg('textMsg');
  setStatus('textStatus', '', 'IDLE');
  document.querySelectorAll('#textStrength i').forEach(b => b.className = '');
});
document.getElementById('textCopy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(document.getElementById('textOutput').value);
  showMsg('textMsg', 'Copied to clipboard.', 'ok');
});

// =========================================================
// FILE PANEL
// =========================================================
let fileMode = 'encrypt';
let selectedFile = null;
wireModeSwitch('file', (mode) => {
  fileMode = mode;
  document.getElementById('fileKdfField').style.display = mode === 'encrypt' ? '' : 'none';
  hideMsg('fileMsg');
  setStatus('fileStatus', '', 'IDLE');
});

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('drag'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
dropzone.addEventListener('drop', (e) => { e.preventDefault(); dropzone.classList.remove('drag'); if (e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]); });
fileInput.addEventListener('change', (e) => { if (e.target.files.length) handleFileSelect(e.target.files[0]); });

function handleFileSelect(file) {
  selectedFile = file;
  document.getElementById('fileInfo').textContent = `${file.name} · ${formatBytes(file.size)}`;
  document.getElementById('fileRun').disabled = false;
  hideMsg('fileMsg');
}

document.getElementById('fileRun').addEventListener('click', async () => {
  const password = document.getElementById('filePassword').value;
  hideMsg('fileMsg');
  if (!password) { showMsg('fileMsg', 'Enter a password first.', 'err'); return; }
  if (!selectedFile) { showMsg('fileMsg', 'Choose a file first.', 'err'); return; }

  const MAX_SIZE = 500 * 1024 * 1024;
  if (selectedFile.size > MAX_SIZE) {
    showMsg('fileMsg', "File is larger than 500 MB. This tool buffers the whole file in memory — for bigger files you'd want a streaming implementation.", 'err');
    return;
  }

  setStatus('fileStatus', '', 'WORKING…');
  const runBtn = document.getElementById('fileRun');
  runBtn.disabled = true;
  try {
    const bytes = new Uint8Array(await selectedFile.arrayBuffer());
    if (fileMode === 'encrypt') {
      const kdfId = parseInt(document.getElementById('fileKdf').value, 10);
      const packed = await encryptBytes(password, bytes, kdfId);
      downloadBytes(packed, selectedFile.name + '.enc');
      setStatus('fileStatus', 'ready', 'ENCRYPTED');
      showMsg('fileMsg', 'Encrypted file downloaded as "' + selectedFile.name + '.enc".', 'ok');
    } else {
      const plainBytes = await decryptBytes(password, bytes);
      const outName = selectedFile.name.endsWith('.enc') ? selectedFile.name.slice(0, -4) : selectedFile.name + '.decrypted';
      downloadBytes(plainBytes, outName);
      setStatus('fileStatus', 'ready', 'DECRYPTED');
      showMsg('fileMsg', 'Decrypted file downloaded as "' + outName + '".', 'ok');
    }
  } catch (err) {
    setStatus('fileStatus', 'error', 'FAILED');
    if (err.message === 'AUTH') showMsg('fileMsg', 'Decryption failed — wrong password, or the file is corrupted/tampered with.', 'err');
    else if (err.message === 'FORMAT') showMsg('fileMsg', "This doesn't look like a file encrypted by this tool (too short or wrong format).", 'err');
    else if (err.message === 'ARGON2_UNAVAILABLE') showMsg('fileMsg', 'Argon2id needs its WASM module from the CDN — check your connection, or re-encrypt using PBKDF2.', 'warn');
    else showMsg('fileMsg', 'Unexpected error: ' + err.message, 'err');
  } finally { runBtn.disabled = false; }
});

document.getElementById('fileClear').addEventListener('click', () => {
  document.getElementById('filePassword').value = '';
  selectedFile = null;
  fileInput.value = '';
  document.getElementById('fileInfo').textContent = '';
  document.getElementById('fileRun').disabled = true;
  hideMsg('fileMsg');
  setStatus('fileStatus', '', 'IDLE');
});

// =========================================================
// ASYMMETRIC core (RSA-OAEP hybrid, ECDH hybrid)
// Packet layout: "CBA1" | algoId(1) | blobLen(2,BE) | blob | iv(12) | ciphertext+tag
//   algoId 0/1 (RSA-OAEP 2048/4096): blob = RSA-OAEP-encrypted random AES-256 key
//   algoId 2/3 (ECDH P-256/P-384):   blob = sender's ephemeral public key (SPKI)
// =========================================================
const ASYM_MAGIC = new TextEncoder().encode('CBA1');

function algoParamsFor(algoId) {
  switch (algoId) {
    case 0: return { genParams: { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, importParams: { name: 'RSA-OAEP', hash: 'SHA-256' }, kind: 'rsa' };
    case 1: return { genParams: { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, importParams: { name: 'RSA-OAEP', hash: 'SHA-256' }, kind: 'rsa' };
    case 2: return { genParams: { name: 'ECDH', namedCurve: 'P-256' }, importParams: { name: 'ECDH', namedCurve: 'P-256' }, kind: 'ecdh' };
    case 3: return { genParams: { name: 'ECDH', namedCurve: 'P-384' }, importParams: { name: 'ECDH', namedCurve: 'P-384' }, kind: 'ecdh' };
    case 4: return { genParams: { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, importParams: { name: 'RSA-PSS', hash: 'SHA-256' }, signParams: { name: 'RSA-PSS', saltLength: 32 }, kind: 'rsa-pss' };
    case 5: return { genParams: { name: 'RSA-PSS', modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, importParams: { name: 'RSA-PSS', hash: 'SHA-256' }, signParams: { name: 'RSA-PSS', saltLength: 32 }, kind: 'rsa-pss' };
    case 6: return { genParams: { name: 'ECDSA', namedCurve: 'P-256' }, importParams: { name: 'ECDSA', namedCurve: 'P-256' }, signParams: { name: 'ECDSA', hash: 'SHA-256' }, kind: 'ecdsa' };
    case 7: return { genParams: { name: 'ECDSA', namedCurve: 'P-384' }, importParams: { name: 'ECDSA', namedCurve: 'P-384' }, signParams: { name: 'ECDSA', hash: 'SHA-384' }, kind: 'ecdsa' };
    default: throw new Error('FORMAT');
  }
}
function algoLabel(algoId) {
  return ['RSA-OAEP-2048', 'RSA-OAEP-4096', 'ECDH-P256', 'ECDH-P384', 'RSA-PSS-2048', 'RSA-PSS-4096', 'ECDSA-P256', 'ECDSA-P384'][algoId] || 'UNKNOWN';
}
function usagesFor(kind, side) {
  // side: 'public' or 'private'
  if (kind === 'rsa') return side === 'public' ? ['encrypt'] : ['decrypt'];
  if (kind === 'ecdh') return side === 'public' ? [] : ['deriveKey', 'deriveBits'];
  if (kind === 'rsa-pss' || kind === 'ecdsa') return side === 'public' ? ['verify'] : ['sign'];
  throw new Error('FORMAT');
}
function genUsagesFor(kind) {
  if (kind === 'rsa') return ['encrypt', 'decrypt'];
  if (kind === 'ecdh') return ['deriveKey', 'deriveBits'];
  return ['sign', 'verify']; // rsa-pss, ecdsa
}

async function generateAsymKeyPair(algoId) {
  const p = algoParamsFor(algoId);
  return crypto.subtle.generateKey(p.genParams, true, genUsagesFor(p.kind));
}
async function exportPublicKeyPem(key) {
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', key));
  return toPem(bytesToBase64(spki), 'PUBLIC KEY');
}
async function exportPrivateKeyPem(key) {
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', key));
  return toPem(bytesToBase64(pkcs8), 'PRIVATE KEY');
}
async function importPublicKeyFromPem(pem, algoId) {
  const p = algoParamsFor(algoId);
  const bytes = base64ToBytes(fromPem(pem));
  return crypto.subtle.importKey('spki', bytes, p.importParams, true, usagesFor(p.kind, 'public'));
}
async function importPrivateKeyFromPem(pem, algoId) {
  const p = algoParamsFor(algoId);
  const bytes = base64ToBytes(fromPem(pem));
  return crypto.subtle.importKey('pkcs8', bytes, p.importParams, true, usagesFor(p.kind, 'private'));
}

function packAsym(algoId, blob, iv, cipherBytes) {
  const out = new Uint8Array(4 + 1 + 2 + blob.length + IV_LEN + cipherBytes.length);
  let off = 0;
  out.set(ASYM_MAGIC, off); off += 4;
  out[off] = algoId; off += 1;
  out[off] = (blob.length >> 8) & 0xff; out[off + 1] = blob.length & 0xff; off += 2;
  out.set(blob, off); off += blob.length;
  out.set(iv, off); off += IV_LEN;
  out.set(cipherBytes, off);
  return out;
}
function unpackAsym(bytes) {
  if (bytes.length < 4 + 1 + 2) throw new Error('FORMAT');
  for (let i = 0; i < 4; i++) if (bytes[i] !== ASYM_MAGIC[i]) throw new Error('FORMAT');
  const algoId = bytes[4];
  const blobLen = (bytes[5] << 8) | bytes[6];
  let off = 7;
  if (bytes.length < off + blobLen + IV_LEN) throw new Error('FORMAT');
  const blob = bytes.slice(off, off + blobLen); off += blobLen;
  const iv = bytes.slice(off, off + IV_LEN); off += IV_LEN;
  const cipher = bytes.slice(off);
  return { algoId, blob, iv, cipher };
}

async function asymEncrypt(algoId, recipientPublicKey, plainBytes) {
  const p = algoParamsFor(algoId);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  if (p.kind === 'rsa') {
    const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
    const rawAes = new Uint8Array(await crypto.subtle.exportKey('raw', aesKey));
    const encAesKey = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, rawAes));
    const cipherBuf = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes));
    return packAsym(algoId, encAesKey, iv, cipherBuf);
  } else {
    const ephemeral = await crypto.subtle.generateKey(p.genParams, true, ['deriveKey', 'deriveBits']);
    const aesKey = await crypto.subtle.deriveKey({ name: 'ECDH', public: recipientPublicKey }, ephemeral.privateKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const ephPubRaw = new Uint8Array(await crypto.subtle.exportKey('spki', ephemeral.publicKey));
    const cipherBuf = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plainBytes));
    return packAsym(algoId, ephPubRaw, iv, cipherBuf);
  }
}
async function asymDecrypt(myPrivatePem, packedBytes) {
  const { algoId, blob, iv, cipher } = unpackAsym(packedBytes);
  const p = algoParamsFor(algoId);
  const myPrivateKey = await importPrivateKeyFromPem(myPrivatePem, algoId);
  if (p.kind === 'rsa') {
    let rawAes;
    try { rawAes = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myPrivateKey, blob)); }
    catch (e) { throw new Error('AUTH'); }
    const aesKey = await crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
    try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher)); }
    catch (e) { throw new Error('AUTH'); }
  } else {
    const senderEphPub = await crypto.subtle.importKey('spki', blob, p.importParams, true, []);
    const aesKey = await crypto.subtle.deriveKey({ name: 'ECDH', public: senderEphPub }, myPrivateKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    try { return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, cipher)); }
    catch (e) { throw new Error('AUTH'); }
  }
}

// ---------- Signing core (RSA-PSS, ECDSA) with replay protection ----------
// A "package" bundles message + timestamp + nonce, and the SIGNATURE COVERS
// ALL THREE — so none of them can be stripped or altered independently of
// the others without breaking the signature.
//
// Signed-bytes layout (what actually gets signed):
//   algoId(1) | ts(8, BE ms-since-epoch) | nonce(16) | msgLen(4, BE) | msg
// Package layout (what gets shared):
//   "CBP1" | algoId(1) | ts(8) | nonce(16) | msgLen(4) | msg | sigLen(2, BE) | sig
const PKG_MAGIC = new TextEncoder().encode('CBP1');
const NONCE_LEN = 16;

function u32be(n) { return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]); }
function readU32be(bytes, off) { return (bytes[off] << 24 | bytes[off+1] << 16 | bytes[off+2] << 8 | bytes[off+3]) >>> 0; }
function u64beFromNumber(n) {
  const big = BigInt(n);
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  view.setBigUint64(0, big, false);
  return out;
}
function readU64beToNumber(bytes, off) {
  const view = new DataView(bytes.buffer, bytes.byteOffset + off, 8);
  return Number(view.getBigUint64(0, false));
}
function concatBytes(arrays) {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function buildSignedBytes(algoId, tsMs, nonce, msgBytes) {
  return concatBytes([new Uint8Array([algoId]), u64beFromNumber(tsMs), nonce, u32be(msgBytes.length), msgBytes]);
}
function packPackage(algoId, tsMs, nonce, msgBytes, sigBytes) {
  const sigLen = new Uint8Array([(sigBytes.length >> 8) & 0xff, sigBytes.length & 0xff]);
  return concatBytes([PKG_MAGIC, new Uint8Array([algoId]), u64beFromNumber(tsMs), nonce, u32be(msgBytes.length), msgBytes, sigLen, sigBytes]);
}
function unpackPackage(bytes) {
  if (bytes.length < 4 + 1 + 8 + NONCE_LEN + 4 + 2) throw new Error('FORMAT');
  for (let i = 0; i < 4; i++) if (bytes[i] !== PKG_MAGIC[i]) throw new Error('FORMAT');
  let off = 4;
  const algoId = bytes[off]; off += 1;
  const tsMs = readU64beToNumber(bytes, off); off += 8;
  const nonce = bytes.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const msgLen = readU32be(bytes, off); off += 4;
  if (bytes.length < off + msgLen + 2) throw new Error('FORMAT');
  const msg = bytes.slice(off, off + msgLen); off += msgLen;
  const sigLen = (bytes[off] << 8) | bytes[off + 1]; off += 2;
  if (bytes.length < off + sigLen) throw new Error('FORMAT');
  const sig = bytes.slice(off, off + sigLen);
  return { algoId, tsMs, nonce, msg, sig };
}

async function asymSignPackage(algoId, privateKey, messageBytes) {
  const p = algoParamsFor(algoId);
  const tsMs = Date.now();
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
  const signedBytes = buildSignedBytes(algoId, tsMs, nonce, messageBytes);
  const sigBuf = await crypto.subtle.sign(p.signParams, privateKey, signedBytes);
  return { packet: packPackage(algoId, tsMs, nonce, messageBytes, new Uint8Array(sigBuf)), tsMs };
}
async function asymVerifyPackage(publicKey, packedBytes) {
  const { algoId, tsMs, nonce, msg, sig } = unpackPackage(packedBytes);
  const p = algoParamsFor(algoId);
  const signedBytes = buildSignedBytes(algoId, tsMs, nonce, msg);
  const valid = await crypto.subtle.verify(p.signParams, publicKey, sig, signedBytes);
  return { valid, algoId, tsMs, nonce, msg };
}

// Session-only replay detector — nonces seen this tab, this load. This is a
// courtesy check, not a security boundary: it resets on refresh and doesn't
// coordinate across tabs, devices, or a server. Real replay protection needs
// a shared, persistent store of consumed nonces, which is out of scope for a
// tool that deliberately keeps no state.
const seenNonces = new Set();

// ---------- Asymmetric UI wiring ----------
wireModeSwitch('asym', (mode) => {
  document.getElementById('asymGenerate').style.display = mode === 'generate' ? '' : 'none';
  document.getElementById('asymEncrypt').style.display = mode === 'encrypt' ? '' : 'none';
  document.getElementById('asymDecrypt').style.display = mode === 'decrypt' ? '' : 'none';
  document.getElementById('asymSign').style.display = mode === 'sign' ? '' : 'none';
  document.getElementById('asymVerify').style.display = mode === 'verify' ? '' : 'none';
  setStatus('asymStatus', '', 'IDLE');
});

let lastGeneratedAlgoId = null;
document.getElementById('genRun').addEventListener('click', async () => {
  hideMsg('genMsg');
  const algoId = parseInt(document.getElementById('asymAlgoGen').value, 10);
  setStatus('asymStatus', '', 'GENERATING…');
  document.getElementById('genRun').disabled = true;
  document.getElementById('keypairGrid').style.display = 'none';
  try {
    const pair = await generateAsymKeyPair(algoId);
    const pubPem = await exportPublicKeyPem(pair.publicKey);
    const privPem = await exportPrivateKeyPem(pair.privateKey);
    document.getElementById('genPubOut').value = pubPem;
    document.getElementById('genPrivOut').value = privPem;
    document.getElementById('keypairGrid').style.display = '';
    lastGeneratedAlgoId = algoId;
    setStatus('asymStatus', 'ready', 'GENERATED');
    showMsg('genMsg', algoLabel(algoId) + ' key pair generated. Copy or download your private key now — it is not saved anywhere.', 'ok');
  } catch (err) {
    setStatus('asymStatus', 'error', 'FAILED');
    showMsg('genMsg', 'Key generation failed: ' + err.message, 'err');
  } finally { document.getElementById('genRun').disabled = false; }
});
document.getElementById('genPubCopy').addEventListener('click', async () => { await navigator.clipboard.writeText(document.getElementById('genPubOut').value); showMsg('genMsg', 'Public key copied.', 'ok'); });
document.getElementById('genPrivCopy').addEventListener('click', async () => { await navigator.clipboard.writeText(document.getElementById('genPrivOut').value); showMsg('genMsg', 'Private key copied — store it somewhere safe.', 'warn'); });
document.getElementById('genPubDl').addEventListener('click', () => downloadText(document.getElementById('genPubOut').value, 'cipherbench-public.pem'));
document.getElementById('genPrivDl').addEventListener('click', () => downloadText(document.getElementById('genPrivOut').value, 'cipherbench-private.pem'));

document.getElementById('asymEncRun').addEventListener('click', async () => {
  hideMsg('asymEncMsg');
  document.getElementById('asymEncOutputWrap').style.display = 'none';
  const pem = document.getElementById('asymRecipientKey').value.trim();
  const message = document.getElementById('asymPlainInput').value;
  if (!pem) { showMsg('asymEncMsg', "Paste the recipient's public key first.", 'err'); return; }
  if (!message) { showMsg('asymEncMsg', 'Enter a message first.', 'err'); return; }

  setStatus('asymStatus', '', 'WORKING…');
  document.getElementById('asymEncRun').disabled = true;
  try {
    let recipientKey = null, matchedAlgoId = null;
    for (const algoId of [2, 3, 0, 1]) { // try ECDH curves first (cheap), then RSA sizes
      try { recipientKey = await importPublicKeyFromPem(pem, algoId); matchedAlgoId = algoId; break; } catch (e) { /* try next */ }
    }
    if (recipientKey === null) throw new Error('KEYFORMAT');
    const plainBytes = new TextEncoder().encode(message);
    const packed = await asymEncrypt(matchedAlgoId, recipientKey, plainBytes);
    document.getElementById('asymEncOutput').value = bytesToBase64(packed);
    document.getElementById('asymEncOutputWrap').style.display = '';
    setStatus('asymStatus', 'ready', 'ENCRYPTED');
    showMsg('asymEncMsg', 'Encrypted with ' + algoLabel(matchedAlgoId) + '.', 'ok');
  } catch (err) {
    setStatus('asymStatus', 'error', 'FAILED');
    if (err.message === 'KEYFORMAT') showMsg('asymEncMsg', "Couldn't read that public key — check it's a full PEM block copied from the Generate tab.", 'err');
    else showMsg('asymEncMsg', 'Encryption failed: ' + err.message, 'err');
  } finally { document.getElementById('asymEncRun').disabled = false; }
});
document.getElementById('asymEncClear').addEventListener('click', () => {
  document.getElementById('asymRecipientKey').value = '';
  document.getElementById('asymPlainInput').value = '';
  document.getElementById('asymEncOutput').value = '';
  document.getElementById('asymEncOutputWrap').style.display = 'none';
  hideMsg('asymEncMsg');
  setStatus('asymStatus', '', 'IDLE');
});
document.getElementById('asymEncCopy').addEventListener('click', async () => { await navigator.clipboard.writeText(document.getElementById('asymEncOutput').value); showMsg('asymEncMsg', 'Copied to clipboard.', 'ok'); });

document.getElementById('asymDecRun').addEventListener('click', async () => {
  hideMsg('asymDecMsg');
  document.getElementById('asymDecOutputWrap').style.display = 'none';
  const pem = document.getElementById('asymMyPrivateKey').value.trim();
  const cipherB64 = document.getElementById('asymCipherInput').value.trim();
  if (!pem) { showMsg('asymDecMsg', 'Paste your private key first.', 'err'); return; }
  if (!cipherB64) { showMsg('asymDecMsg', 'Paste the ciphertext first.', 'err'); return; }

  setStatus('asymStatus', '', 'WORKING…');
  document.getElementById('asymDecRun').disabled = true;
  try {
    let packed;
    try { packed = base64ToBytes(cipherB64); } catch (e) { throw new Error('FORMAT'); }
    const plainBytes = await asymDecrypt(pem, packed);
    document.getElementById('asymDecOutput').value = new TextDecoder().decode(plainBytes);
    document.getElementById('asymDecOutputWrap').style.display = '';
    setStatus('asymStatus', 'ready', 'DECRYPTED');
  } catch (err) {
    setStatus('asymStatus', 'error', 'FAILED');
    if (err.message === 'AUTH') showMsg('asymDecMsg', "Decryption failed — this ciphertext wasn't encrypted to this private key, or it's corrupted.", 'err');
    else if (err.message === 'FORMAT') showMsg('asymDecMsg', "That doesn't look like valid ciphertext from this tool.", 'err');
    else showMsg('asymDecMsg', "Couldn't decrypt — check the private key matches the algorithm used to encrypt (" + err.message + ").", 'err');
  } finally { document.getElementById('asymDecRun').disabled = false; }
});
document.getElementById('asymDecClear').addEventListener('click', () => {
  document.getElementById('asymMyPrivateKey').value = '';
  document.getElementById('asymCipherInput').value = '';
  document.getElementById('asymDecOutput').value = '';
  document.getElementById('asymDecOutputWrap').style.display = 'none';
  hideMsg('asymDecMsg');
  setStatus('asymStatus', '', 'IDLE');
});

document.getElementById('asymSignRun').addEventListener('click', async () => {
  hideMsg('asymSignMsg');
  document.getElementById('asymSignOutputWrap').style.display = 'none';
  const pem = document.getElementById('asymSignPrivateKey').value.trim();
  const message = document.getElementById('asymSignMessage').value;
  if (!pem) { showMsg('asymSignMsg', 'Paste your private key first.', 'err'); return; }
  if (!message) { showMsg('asymSignMsg', 'Enter a message to sign first.', 'err'); return; }

  setStatus('asymStatus', '', 'WORKING…');
  document.getElementById('asymSignRun').disabled = true;
  try {
    let privateKey = null, matchedAlgoId = null;
    for (const algoId of [6, 7, 4, 5]) { // ECDSA curves first (cheap), then RSA-PSS sizes
      try { privateKey = await importPrivateKeyFromPem(pem, algoId); matchedAlgoId = algoId; break; } catch (e) { /* try next */ }
    }
    if (privateKey === null) throw new Error('KEYFORMAT');
    const { packet, tsMs } = await asymSignPackage(matchedAlgoId, privateKey, new TextEncoder().encode(message));
    document.getElementById('asymSignOutput').value = bytesToBase64(packet);
    document.getElementById('asymSignOutputWrap').style.display = '';
    setStatus('asymStatus', 'ready', 'SIGNED');
    showMsg('asymSignMsg', 'Signed with ' + algoLabel(matchedAlgoId) + ' at ' + new Date(tsMs).toLocaleTimeString() + '.', 'ok');
  } catch (err) {
    setStatus('asymStatus', 'error', 'FAILED');
    if (err.message === 'KEYFORMAT') showMsg('asymSignMsg', "Couldn't read that private key — make sure it's a signing key (RSA-PSS or ECDSA), not an encryption key (RSA-OAEP/ECDH).", 'err');
    else showMsg('asymSignMsg', 'Signing failed: ' + err.message, 'err');
  } finally { document.getElementById('asymSignRun').disabled = false; }
});
document.getElementById('asymSignClear').addEventListener('click', () => {
  document.getElementById('asymSignPrivateKey').value = '';
  document.getElementById('asymSignMessage').value = '';
  document.getElementById('asymSignOutput').value = '';
  document.getElementById('asymSignOutputWrap').style.display = 'none';
  hideMsg('asymSignMsg');
  setStatus('asymStatus', '', 'IDLE');
});
document.getElementById('asymSignCopy').addEventListener('click', async () => { await navigator.clipboard.writeText(document.getElementById('asymSignOutput').value); showMsg('asymSignMsg', 'Copied to clipboard.', 'ok'); });

document.getElementById('asymVerifyRun').addEventListener('click', async () => {
  hideMsg('asymVerifyMsg');
  document.getElementById('asymVerifyResultWrap').style.display = 'none';
  const pubPem = document.getElementById('asymVerifyPublicKey').value.trim();
  const pkgB64 = document.getElementById('asymVerifyPackage').value.trim();
  const windowMs = parseInt(document.getElementById('asymFreshnessWindow').value, 10);
  if (!pubPem) { showMsg('asymVerifyMsg', "Paste the signer's public key first.", 'err'); return; }
  if (!pkgB64) { showMsg('asymVerifyMsg', 'Paste the signed package first.', 'err'); return; }

  setStatus('asymStatus', '', 'WORKING…');
  document.getElementById('asymVerifyRun').disabled = true;
  try {
    let pkgBytes;
    try { pkgBytes = base64ToBytes(pkgB64); } catch (e) { throw new Error('FORMAT'); }

    // Parse first so we know which algorithm to import the public key as.
    const parsed = unpackPackage(pkgBytes);
    let publicKey;
    try { publicKey = await importPublicKeyFromPem(pubPem, parsed.algoId); }
    catch (e) { throw new Error('KEYFORMAT'); }

    const { valid, tsMs, nonce, msg } = await asymVerifyPackage(publicKey, pkgBytes);
    const ageMs = Date.now() - tsMs;
    const nonceHex = bytesToHex(nonce);
    const CLOCK_SKEW_TOLERANCE_MS = 2 * 60 * 1000;

    let freshnessNote = '';
    let freshnessOk = true;
    if (ageMs < -CLOCK_SKEW_TOLERANCE_MS) { freshnessOk = false; freshnessNote = 'Timestamp is in the future — check clocks, or treat as suspicious.'; }
    else if (windowMs > 0 && ageMs > windowMs) { freshnessOk = false; freshnessNote = 'Signature is older than the freshness window (' + Math.round(ageMs / 1000) + 's old).'; }

    let replayNote = '';
    let replaySeen = false;
    if (valid) {
      replaySeen = seenNonces.has(nonceHex);
      if (replaySeen) replayNote = 'This exact signed package has already been verified once in this session.';
      else seenNonces.add(nonceHex);
    }

    document.getElementById('asymVerifyResultMsg').value = new TextDecoder().decode(msg);
    document.getElementById('asymVerifyResultWrap').style.display = valid ? '' : 'none';

    const whenStr = new Date(tsMs).toLocaleString();
    if (!valid) {
      setStatus('asymStatus', 'error', 'INVALID');
      showMsg('asymVerifyMsg', "✗ Invalid signature — the package, key, or contents don't match.", 'err');
    } else if (!freshnessOk) {
      setStatus('asymStatus', 'error', 'STALE');
      showMsg('asymVerifyMsg', '✓ Signature is authentic, signed ' + whenStr + ', but flagged: ' + freshnessNote, 'warn');
    } else if (replaySeen) {
      setStatus('asymStatus', 'error', 'REPLAY?');
      showMsg('asymVerifyMsg', '✓ Signature is authentic and fresh, but ⚠ ' + replayNote + ' (session-only check — not a substitute for server-side replay protection).', 'warn');
    } else {
      setStatus('asymStatus', 'ready', 'VALID');
      showMsg('asymVerifyMsg', '✓ Valid, fresh signature — signed ' + whenStr + ' and not previously seen this session.', 'ok');
    }
  } catch (err) {
    setStatus('asymStatus', 'error', 'FAILED');
    if (err.message === 'FORMAT') showMsg('asymVerifyMsg', "That doesn't look like a valid signed package from this tool.", 'err');
    else if (err.message === 'KEYFORMAT') showMsg('asymVerifyMsg', "Couldn't read that public key, or it doesn't match the package's algorithm.", 'err');
    else showMsg('asymVerifyMsg', 'Verification failed: ' + err.message, 'err');
  } finally { document.getElementById('asymVerifyRun').disabled = false; }
});
document.getElementById('asymVerifyClear').addEventListener('click', () => {
  document.getElementById('asymVerifyPublicKey').value = '';
  document.getElementById('asymVerifyPackage').value = '';
  document.getElementById('asymVerifyResultMsg').value = '';
  document.getElementById('asymVerifyResultWrap').style.display = 'none';
  hideMsg('asymVerifyMsg');
  setStatus('asymStatus', '', 'IDLE');
});

// =========================================================
// HASH PANEL
// =========================================================
let hashInputMode = 'hash-text';
let hashSelectedFile = null;
wireModeSwitch('hash', (mode) => {
  hashInputMode = mode;
  document.getElementById('hashTextField').style.display = mode === 'hash-text' ? '' : 'none';
  document.getElementById('hashFileField').style.display = mode === 'hash-file' ? '' : 'none';
  document.getElementById('hashOutput').textContent = '—';
  hideMsg('hashMsg');
  setStatus('hashStatus', '', 'IDLE');
});

const hashDropzone = document.getElementById('hashDropzone');
const hashFileInput = document.getElementById('hashFileInput');
hashDropzone.addEventListener('click', () => hashFileInput.click());
hashDropzone.addEventListener('dragover', (e) => { e.preventDefault(); hashDropzone.classList.add('drag'); });
hashDropzone.addEventListener('dragleave', () => hashDropzone.classList.remove('drag'));
hashDropzone.addEventListener('drop', (e) => {
  e.preventDefault(); hashDropzone.classList.remove('drag');
  if (e.dataTransfer.files.length) { hashSelectedFile = e.dataTransfer.files[0]; document.getElementById('hashFileInfo').textContent = `${hashSelectedFile.name} · ${formatBytes(hashSelectedFile.size)}`; }
});
hashFileInput.addEventListener('change', (e) => {
  if (e.target.files.length) { hashSelectedFile = e.target.files[0]; document.getElementById('hashFileInfo').textContent = `${hashSelectedFile.name} · ${formatBytes(hashSelectedFile.size)}`; }
});

document.getElementById('hashRun').addEventListener('click', async () => {
  hideMsg('hashMsg');
  const algo = document.getElementById('hashAlgo').value;
  setStatus('hashStatus', '', 'WORKING…');
  try {
    let bytes;
    if (hashInputMode === 'hash-text') {
      const text = document.getElementById('hashInput').value;
      if (!text) { showMsg('hashMsg', 'Enter some text first.', 'err'); setStatus('hashStatus', '', 'IDLE'); return; }
      bytes = new TextEncoder().encode(text);
    } else {
      if (!hashSelectedFile) { showMsg('hashMsg', 'Choose a file first.', 'err'); setStatus('hashStatus', '', 'IDLE'); return; }
      bytes = new Uint8Array(await hashSelectedFile.arrayBuffer());
    }
    const digestBuf = await crypto.subtle.digest(algo, bytes);
    const hex = bytesToHex(new Uint8Array(digestBuf));
    document.getElementById('hashOutput').textContent = hex;
    setStatus('hashStatus', 'ready', 'DONE');
    const compareVal = document.getElementById('hashCompare').value.trim().toLowerCase();
    if (compareVal) {
      showMsg('hashMsg', compareVal === hex.toLowerCase() ? 'Match — hashes are identical.' : 'No match — hashes differ.', compareVal === hex.toLowerCase() ? 'ok' : 'err');
    }
  } catch (err) {
    setStatus('hashStatus', 'error', 'FAILED');
    showMsg('hashMsg', 'Unexpected error: ' + err.message, 'err');
  }
});
document.getElementById('hashClear').addEventListener('click', () => {
  document.getElementById('hashInput').value = '';
  document.getElementById('hashCompare').value = '';
  document.getElementById('hashOutput').textContent = '—';
  hashSelectedFile = null;
  hashFileInput.value = '';
  document.getElementById('hashFileInfo').textContent = '';
  hideMsg('hashMsg');
  setStatus('hashStatus', '', 'IDLE');
});
