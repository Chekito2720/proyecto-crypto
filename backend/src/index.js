require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");

const authRoutes = require("./routes/auth");
const walletRoutes = require("./routes/wallet");
const trxRoutes = require("./routes/transaction");

const fs = require("fs");
const app = express();

app.use(express.json({ limit: "10mb" }));
app.use(cors());
app.use(helmet());

// Servir la clave pública del servidor
app.get("/api/publicKey", (req, res) => {
  const pub = fs.readFileSync(process.env.SERVER_PUBLIC_KEY_PATH, "utf8");
  res.json({ pem: pub });
});

app.use("/api/auth", authRoutes);
app.use("/api/wallet", walletRoutes);
app.use("/api/transaction", trxRoutes);

app.listen(process.env.PORT, () =>
  console.log(`Backend running on port ${process.env.PORT}`)
);
