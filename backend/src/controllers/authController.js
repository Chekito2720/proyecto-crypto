const pool = require("../db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const SALT = 12;

async function register(req, res) {
  try {
    const { email, password, publicKeyPem } = req.body;
    if (!email || !password || !publicKeyPem)
      return res
        .status(400)
        .json({ error: "email, password and publicKeyPem required" });

    const hash = await bcrypt.hash(password, SALT);
    const [result] = await pool.query(
      "INSERT INTO users (email, password_hash, public_key_pem) VALUES (?, ?, ?)",
      [email, hash, publicKeyPem]
    );
    res.json({ ok: true, userId: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
}

async function login(req, res) {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "email and password required" });
    const [rows] = await pool.query(
      "SELECT id, password_hash FROM users WHERE email = ?",
      [email]
    );
    if (!rows.length) return res.status(401).json({ error: "User not found" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, email }, process.env.JWT_SECRET, {
      expiresIn: "3h",
    });
    res.json({ ok: true, token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
}

module.exports = { register, login };
