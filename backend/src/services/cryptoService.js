const crypto = require("crypto");
const fs = require("fs");
require("dotenv").config();

// Server private key for RSA-OAEP unwrap and optionally signing server messages
const PRIVATE_KEY = fs.readFileSync(
  process.env.SERVER_PRIVATE_KEY_PATH,
  "utf8"
);

function unwrapKeyRSA(wrappedKeyBuffer) {
  return crypto.privateDecrypt(
    {
      key: PRIVATE_KEY,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    wrappedKeyBuffer
  );
}

// AES-GCM decryption (ciphertext includes tag at end)
function decryptAESGCM(aesKeyBuffer, ivBuffer, ciphertextBuffer) {
  const tagLength = 16;
  if (ciphertextBuffer.length < tagLength)
    throw new Error("ciphertext too short");
  const tag = ciphertextBuffer.slice(ciphertextBuffer.length - tagLength);
  const encrypted = ciphertextBuffer.slice(
    0,
    ciphertextBuffer.length - tagLength
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    aesKeyBuffer,
    ivBuffer
  );
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);
  return decrypted; // Buffer
}

// AES-GCM encryption helper (server-side custodial wallet encryption)
function encryptAESGCM(aesKeyBuffer, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKeyBuffer, iv);
  const encrypted = Buffer.concat([
    cipher.update(Buffer.from(plaintext)),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return { iv, ciphertext: Buffer.concat([encrypted, tag]) };
}

// verify ECDSA or RSA signature (publicKeyPem, data Buffer, signature Buffer)
// We'll implement verification for the signature algorithm the client uses (ECDSA with SHA-256)
function verifySignature(publicKeyPem, dataBuffer, signatureBuffer) {
  // Node's crypto.verify can handle ECDSA P-256 signatures in DER format if client exports properly
  return crypto.verify("sha256", dataBuffer, publicKeyPem, signatureBuffer);
}

module.exports = {
  unwrapKeyRSA,
  decryptAESGCM,
  encryptAESGCM,
  verifySignature,
};
