// JavaScript source code
// aiController.js
// ------------------------------------------------------------
// Orchestrates one /ai/chat request:
//   classify -> (math | keyword lookup | teach-me) -> log -> reply
//
// Expects a mysql2/promise pool to be passed in via init(pool).
// ------------------------------------------------------------

const {
  classifyMessage,
  extractKeywords,
  detectMath,
  evaluateMath,
  FALLBACK_STOPWORDS
} = require('./nlpEngine');

let pool = null;
let stopwordSet = FALLBACK_STOPWORDS;

/** Call once at server startup, after your mysql2 pool is created. */
function init(mysqlPool) {
  pool = mysqlPool;
  loadStopwords().catch(err =>
    console.error('AI engine: failed to load stopwords, using fallback list', err)
  );
}

async function loadStopwords() {
  const [rows] = await pool.query('SELECT word FROM stopwords');
  if (rows.length) {
    stopwordSet = new Set(rows.map(r => r.word.toLowerCase()));
  }
}

async function ensureSession(sessionId, userId) {
  await pool.query(
    `INSERT INTO chat_sessions (session_id, user_id)
     VALUES (?, ?)
     ON DUPLICATE KEY UPDATE last_active = CURRENT_TIMESTAMP, user_id = COALESCE(VALUES(user_id), user_id)`,
    [sessionId, userId || null]
  );
}

async function getRandomScript(category) {
  const [rows] = await pool.query(
    'SELECT content FROM bot_scripts WHERE category = ? ORDER BY RAND() LIMIT 1',
    [category]
  );
  return rows.length ? rows[0].content : null;
}

async function logChat({ sessionId, userId, message, messageType, isMath, botReply }) {
  await pool.query(
    `INSERT INTO chat_logs (session_id, user_id, message, message_type, is_math, bot_reply)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [sessionId, userId || null, message, messageType, isMath ? 1 : 0, botReply]
  );
}

/** Upserts keywords and returns their ids. */
async function getOrCreateKeywordIds(conn, keywords) {
  const ids = [];
  for (const kw of keywords) {
    await conn.query('INSERT IGNORE INTO keywords (keyword) VALUES (?)', [kw]);
    const [rows] = await conn.query('SELECT id FROM keywords WHERE keyword = ?', [kw]);
    if (rows.length) ids.push(rows[0].id);
  }
  return ids;
}

/**
 * Finds the best-matching knowledge_base row by keyword overlap.
 * Returns { id, answer_text, matchCount } or null.
 */
async function findBestAnswer(keywords) {
  if (!keywords.length) return null;

  const placeholders = keywords.map(() => '?').join(',');
  const [rows] = await pool.query(
    `SELECT kb.id, kb.answer_text, COUNT(*) AS match_count
     FROM knowledge_base kb
     JOIN knowledge_base_keywords kbk ON kbk.knowledge_base_id = kb.id
     JOIN keywords k ON k.id = kbk.keyword_id
     WHERE k.keyword IN (${placeholders})
     GROUP BY kb.id, kb.answer_text
     ORDER BY match_count DESC, kb.hit_count DESC
     LIMIT 1`,
    keywords
  );

  if (!rows.length) return null;

  // Require at least a 40% keyword overlap to avoid weak/noisy matches.
  const best = rows[0];
  if (best.match_count / keywords.length < 0.4) return null;

  return best;
}

async function incrementHitCount(kbId) {
  await pool.query('UPDATE knowledge_base SET hit_count = hit_count + 1 WHERE id = ?', [kbId]);
}

async function findPendingQuestion(sessionId) {
  const [rows] = await pool.query(
    `SELECT id, question_text FROM pending_questions
     WHERE session_id = ? AND status = 'waiting'
     ORDER BY created_at DESC LIMIT 1`,
    [sessionId]
  );
  return rows.length ? rows[0] : null;
}

async function resolvePendingQuestion(pendingId, questionText, answerText, userId) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [kbResult] = await conn.query(
      `INSERT INTO knowledge_base (question_text, answer_text, source, taught_by_user_id)
       VALUES (?, ?, 'user_taught', ?)`,
      [questionText, answerText, userId || null]
    );
    const kbId = kbResult.insertId;

    const keywords = extractKeywords(questionText, stopwordSet);
    const keywordIds = await getOrCreateKeywordIds(conn, keywords);
    for (const kwId of keywordIds) {
      await conn.query(
        'INSERT IGNORE INTO knowledge_base_keywords (knowledge_base_id, keyword_id) VALUES (?, ?)',
        [kbId, kwId]
      );
    }

    await conn.query(
      `UPDATE pending_questions SET status = 'resolved', resolved_at = NOW() WHERE id = ?`,
      [pendingId]
    );

    await conn.commit();
    return { kbId, keywords };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function createPendingQuestion(sessionId, userId, questionText, keywords) {
  await pool.query(
    `INSERT INTO pending_questions (session_id, user_id, question_text, keywords_text)
     VALUES (?, ?, ?, ?)`,
    [sessionId, userId || null, questionText, keywords.join(', ')]
  );
}

/**
 * Main entry point — plug this into your Express route:
 *   router.post('/chat', aiController.handleChat);
 */
async function handleChat(req, res) {
  try {
    const { message, session_id: sessionId } = req.body;
    const userId = req.user ? req.user.id : (req.body.user_id || null); // adapt to your auth middleware

    if (!message || !sessionId) {
      return res.status(400).json({ success: false, message: 'message and session_id are required' });
    }

    await ensureSession(sessionId, userId);

    const messageType = classifyMessage(message);
    let botReply;
    let isMath = false;

    if (messageType === 'statement') {
      const pending = await findPendingQuestion(sessionId);

      if (pending) {
        await resolvePendingQuestion(pending.id, pending.question_text, message, userId);
        const flavor = await getRandomScript('general');
        botReply = `Thanks — I've learned that! 🎓${flavor ? ' ' + flavor : ''}`;
      } else {
        const flavor = await getRandomScript('idle');
        botReply = flavor || "Got it, thanks for letting me know!";
      }
    } else {
      // messageType === 'question'
      const { isMath: mathDetected, expression } = detectMath(message);
      isMath = mathDetected;

      if (mathDetected) {
        const { success, result, error } = evaluateMath(expression);
        await pool.query(
          `INSERT INTO math_queries_log (session_id, raw_message, expression, result, success)
           VALUES (?, ?, ?, ?, ?)`,
          [sessionId, message, expression, success ? String(result) : null, success ? 1 : 0]
        );

        const flavor = await getRandomScript('math');
        if (success) {
          botReply = `${expression} = ${result}${flavor ? ' — ' + flavor : ''}`;
        } else {
          botReply = `I couldn't work that expression out (${error}). Mind rephrasing it?`;
        }
      } else {
        const keywords = extractKeywords(message, stopwordSet);
        const best = await findBestAnswer(keywords);

        if (best) {
          await incrementHitCount(best.id);
          const flavor = await getRandomScript('general');
          botReply = `${best.answer_text}${flavor ? '\n\n💡 ' + flavor : ''}`;
        } else {
          await createPendingQuestion(sessionId, userId, message, keywords);
          botReply = "I don't know that one yet — can you tell me the answer? I'll remember it for next time!";
        }
      }
    }

    await logChat({ sessionId, userId, message, messageType, isMath, botReply });

    return res.json({ success: true, reply: botReply, type: messageType, is_math: isMath });
  } catch (err) {
    console.error('AI chat error:', err);
    return res.status(500).json({ success: false, message: 'Something went wrong processing that.' });
  }
}

module.exports = { init, handleChat };