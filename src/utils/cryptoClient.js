// ===============================
//  BASE64 HELPERS
// ===============================
export function u8ToBase64(u8) {
  return btoa(String.fromCharCode(...u8));
}

export function base64ToU8(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// ===============================
//  RAW → DER para ECDSA P-256
// ===============================
export function rawToDer(rawSig) {
  const raw = new Uint8Array(rawSig);
  const r = raw.slice(0, 32);
  const s = raw.slice(32);

  function trim(buf) {
    let i = 0;
    while (i < buf.length - 1 && buf[i] === 0) i++;
    return buf.slice(i);
  }

  const rTrim = trim(r);
  const sTrim = trim(s);

  function toInteger(bytes) {
    if (bytes[0] & 0x80) {
      return Uint8Array.from([0, ...bytes]);
    }
    return bytes;
  }

  const rInt = toInteger(rTrim);
  const sInt = toInteger(sTrim);

  const len = 2 + rInt.length + 2 + sInt.length;
  const seq = new Uint8Array(2 + len);
  let o = 0;

  seq[o++] = 0x30;
  seq[o++] = len;

  seq[o++] = 0x02;
  seq[o++] = rInt.length;
  seq.set(rInt, o);
  o += rInt.length;

  seq[o++] = 0x02;
  seq[o++] = sInt.length;
  seq.set(sInt, o);

  return seq;
}

// ===============================
//  Importar clave privada ECDSA JWK
// ===============================
export async function importPrivateKeyFromJWK(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );
}

// ===============================
//  Firma ECDSA (RAW 64 bytes)
// ===============================
export async function signData(privateKey, text) {
  const enc = new TextEncoder();
  return new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      enc.encode(text)
    )
  );
}

// ===============================
//  AES-256 GCM KEY
// ===============================
export async function generateAESKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

// ===============================
//  AES-GCM ENCRYPT
// ===============================
export async function aesEncrypt(aesKey, plaintext) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      aesKey,
      enc.encode(plaintext)
    )
  );

  return { iv, ciphertext };
}

// ===============================
//  Import RSA Public Key PEM
// ===============================
async function importRSAPublicKey(pem) {
  const b64 = pem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\n/g, "");

  const der = base64ToU8(b64);

  return crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"]
  );
}

// ===============================
//  Wrap AES Key with RSA Public
// ===============================
export async function wrapAESKey(aesKey, serverPublicPem) {
  const rsaPubKey = await importRSAPublicKey(serverPublicPem);

  const wrapped = await crypto.subtle.wrapKey("raw", aesKey, rsaPubKey, {
    name: "RSA-OAEP",
  });

  return new Uint8Array(wrapped);
}

// =====================================================
//  🔥 🔥 🔥  FUNCIONES QUE TE FALTABAN  🔥 🔥 🔥
// =====================================================

// ===============================
//  RSA 4096 KEYPAIR
// ===============================
export async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// ===============================
//  Export PUBLIC key → PEM
// ===============================
export async function exportPublicKeyToPEM(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  const b64 = u8ToBase64(new Uint8Array(spki));

  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

// ===============================
//  Export PRIVATE key → JWK
// ===============================
export async function exportPrivateKeyJWK(privateKey) {
  return await crypto.subtle.exportKey("jwk", privateKey);
}
