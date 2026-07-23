// JavaScript source code
// ai.routes.js
// ------------------------------------------------------------
// Mount in your existing server.js, e.g.:
//
//   const mysql = require('mysql2/promise');
//   const aiController = require('./aiController');
//   const aiRoutes = require('./ai.routes');
//
//   const pool = mysql.createPool({ ...your existing config... });
//   aiController.init(pool);
//
//   app.use('/ai', aiRoutes);
//
// This replaces the old OpenAI-backed /ai/chat handler entirely —
// no external API key or network call needed anymore.
// ------------------------------------------------------------

const express = require('express');
const router = express.Router();
const aiController = require('./aiController');

router.post('/chat', aiController.handleChat);

module.exports = router;