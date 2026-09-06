const express = require("express");
const router = express.Router();
const aiController = require("./aiController");

router.post("/chat", aiController.handleChat);

module.exports = router;