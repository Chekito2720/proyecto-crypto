const express = require("express");
const router = express.Router();
const { receiveTransaction } = require("../controllers/transactionController");

router.post("/send", express.json({ limit: "10mb" }), receiveTransaction);

module.exports = router;
