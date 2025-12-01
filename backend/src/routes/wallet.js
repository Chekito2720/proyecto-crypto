const express = require("express");
const router = express.Router();
const {
  createCustodialWallet,
  getWallet,
} = require("../controllers/walletController");
const auth = require("../middleware/authMiddleware");

router.post("/custodial", createCustodialWallet); // optional; requires body.userId
router.get("/", auth, getWallet);

module.exports = router;
