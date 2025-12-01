const pool = require("../db");
const {
  unwrapKeyRSA,
  decryptAESGCM,
  verifySignature, // <-- versión nueva RAW+DER
} = require("../services/cryptoService");

async function receiveTransaction(req, res) {
  try {
    // 1. Obtener datos crudos
    const { wrappedKey, iv, ciphertext, signature, senderId } = req.body;

    console.log("== RAW BODY RECEIVED ==", req.body);

    if (!wrappedKey || !iv || !ciphertext || !signature || !senderId) {
      return res.status(400).json({ error: "Missing fields" });
    }

    // 2. Buffers
    const wrappedBuf = Buffer.from(wrappedKey, "base64");
    const ivBuf = Buffer.from(iv, "base64");
    const cipherBuf = Buffer.from(ciphertext, "base64");
    const sigBuf = Buffer.from(signature, "base64");

    // 3. Desempaquetar AES
    const aesKeyBuf = unwrapKeyRSA(wrappedBuf);

    // 4. Descifrar AES-GCM
    const decryptedBuf = decryptAESGCM(aesKeyBuf, ivBuf, cipherBuf);

    const decryptedText = decryptedBuf.toString("utf8");

    console.log("== DECRYPTED TEXT FROM CLIENT ==");
    console.log(decryptedText);

    // 5. Leer datos
    const trx = JSON.parse(decryptedText);

    if (String(senderId) !== String(trx.senderId)) {
      return res.status(403).json({ error: "Sender ID mismatch" });
    }

    // 6. Obtener llave pública
    const [rows] = await pool.query(
      "SELECT public_key_pem FROM users WHERE id=?",
      [senderId]
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Sender not found" });
    }

    const publicKeyPem = rows[0].public_key_pem;

    // 7. Validar firma — usando el buffer EXACTO que firmó el cliente
    const isValid = verifySignature(publicKeyPem, decryptedBuf, sigBuf);

    if (!isValid) {
      console.error("Firma inválida. Payload:", decryptedText);
      return res.status(400).json({ error: "INVALID_SIGNATURE" });
    }

    // 8. Guardar transacción
    await pool.query(
      `INSERT INTO transactions 
        (sender_id, receiver_id, amount, ciphertext, iv, wrapped_key, signature)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        trx.senderId,
        trx.receiverId,
        trx.amount,
        ciphertext,
        iv,
        wrappedKey,
        signature,
      ]
    );

    res.json({ ok: true, message: "Transaction accepted" });
  } catch (err) {
    console.error("Error en receiveTransaction:", err);
    return res
      .status(500)
      .json({ error: "Internal Server Error processing transaction" });
  }
}

module.exports = { receiveTransaction };
  