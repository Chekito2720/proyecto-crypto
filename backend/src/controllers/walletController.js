const pool = require("../db");
const { encryptAESGCM } = require("../services/cryptoService");
require("dotenv").config();

const MASTER_KEY = Buffer.from(process.env.MASTER_AES_KEY_BASE64, "base64"); // 32 bytes

async function createCustodialWallet(req, res) {
  // Create custodial wallet for a user (server generates ecc key pair, encrypts private key with MASTER_KEY)
  try {
    const { userId, initialBalance } = req.body;
    if (!userId) return res.status(400).json({ error: "userId required" });

    // Generate ECC keypair server-side for custodial wallet (PEM)
    const { publicKey, privateKey } = require("crypto").generateKeyPairSync(
      "ec",
      {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
      }
    );

    // Encrypt privateKey PEM and balance using MASTER_KEY
    const encPriv = encryptAESGCM(MASTER_KEY, privateKey);
    const encBalance = encryptAESGCM(MASTER_KEY, String(initialBalance || 0));

    await pool.query(
      "INSERT INTO wallets (user_id, private_key_encrypted, iv, balance_encrypted) VALUES (?, ?, ?, ?)",
      [userId, encPriv.ciphertext, encPriv.iv, encBalance.ciphertext]
    );

    res.json({ ok: true, publicKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
}

async function getWallet(req, res) {
  try {
    const userId = req.user.id;
    const [rows] = await pool.query(
      "SELECT id, private_key_encrypted, iv, balance_encrypted FROM wallets WHERE user_id=? LIMIT 1",
      [userId]
    );
    if (!rows.length)
      return res.status(404).json({ error: "Wallet not found" });

    // For demo we won't decrypt private key here (custodial) — but we can decrypt balance for display
    res.json({ wallet: { id: rows[0].id } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
}

module.exports = { createCustodialWallet, getWallet };
