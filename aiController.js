// aiController.js
// ------------------------------------------------------------
// Orchestrates one /ai/chat request:
//   classify -> (math | pending-answer | greeting | keyword lookup
//   -> web search fallback -> teach-me) -> log -> reply
//
// Expects a mysql2/promise pool to be passed in via init(pool).
// ------------------------------------------------------------

const {
  classifyMessage,
  extractKeywords,
  detectMath,
  detectGreeting,
  evaluateMath,
  FALLBACK_STOPWORDS
} = require('./nlpEngine');

const { searchWeb } = require('./webSearchEngine');
const contextEngine = require('./contextEngine');

let pool = null;
let stopwordSet = FALLBACK_STOPWORDS;

// Max web searches a single session can trigger per hour. Keeps API
// costs bounded and stops someone from hammering the search provider
// through the chat widget.
const SEARCH_RATE_LIMIT_PER_HOUR = 15;

// Web answers are trimmed to this length before being shown in chat —
// the full text is always still reachable via the source link.
const WEB_ANSWER_MAX_CHARS = 500;

/** Call once at server startup, after your mysql2 pool is created. */
function init(mysqlPool) {
  pool = mysqlPool;
  contextEngine.init(mysqlPool);
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

async function logChat({ sessionId, userId, message, messageType, isMath, botReply, keywords }) {
  const keywordsText = keywords && keywords.length ? keywords.join(',') : null;
  await pool.query(
    `INSERT INTO chat_logs (session_id, user_id, message, message_type, is_math, bot_reply, keywords_text)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, userId || null, message, messageType, isMath ? 1 : 0, botReply, keywordsText]
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

// ── Web search fallback ──────────────────────────────────────────

async function canSearchThisSession(sessionId) {
  const [rows] = await pool.query(
    `SELECT COUNT(*) AS cnt FROM web_search_log
     WHERE session_id = ? AND created_at > (NOW() - INTERVAL 1 HOUR)`,
    [sessionId]
  );
  return rows[0].cnt < SEARCH_RATE_LIMIT_PER_HOUR;
}

async function logWebSearch({ sessionId, userId, query, provider, success, title, url }) {
  await pool.query(
    `INSERT INTO web_search_log (session_id, user_id, query, provider, success, result_title, result_url)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [sessionId, userId || null, query, provider || null, success ? 1 : 0, title || null, url || null]
  );
}

/**
 * Attempts a web search for `message`, respecting the per-session
 * rate limit. Logs the attempt either way. Returns the search result
 * object or null.
 */
async function tryWebSearch(sessionId, userId, message) {
  const allowed = await canSearchThisSession(sessionId);
  if (!allowed) return null;

  const result = await searchWeb(message);
  await logWebSearch({
    sessionId,
    userId,
    query: message,
    provider: result?.provider,
    success: !!result,
    title: result?.title,
    url: result?.url,
  });
  return result;
}

/** Formats a web search result into a chat-friendly reply with source link. */
function formatWebAnswer(result) {
  let extract = result.extract.trim();
  if (extract.length > WEB_ANSWER_MAX_CHARS) {
    extract = extract.slice(0, WEB_ANSWER_MAX_CHARS).trim() + '…';
  }
  const source = result.url ? `\n\n🌐 Source: ${result.title} — ${result.url}` : '';
  return `${extract}${source}`;
}

/**
 * Caches a web search answer into knowledge_base (source='web_search')
 * so the NEXT time someone asks something with similar keywords, it's
 * an instant DB hit instead of another external API call.
 */
async function cacheWebAnswer(questionText, result, keywords) {
  if (!keywords.length) return; // nothing to index it by — skip caching
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [kbResult] = await conn.query(
      `INSERT INTO knowledge_base (question_text, answer_text, source) VALUES (?, ?, 'web_search')`,
      [questionText, result.extract.trim()]
    );
    const kbId = kbResult.insertId;

    const keywordIds = await getOrCreateKeywordIds(conn, keywords);
    for (const kwId of keywordIds) {
      await conn.query(
        'INSERT IGNORE INTO knowledge_base_keywords (knowledge_base_id, keyword_id) VALUES (?, ?)',
        [kbId, kwId]
      );
    }

    await conn.commit();
  } catch (err) {
    await conn.rollback();
    console.error('[cacheWebAnswer]', err.message);
  } finally {
    conn.release();
  }
}

/**
 * Main entry point — plug this into your Express route:
 *   router.post('/chat', aiController.handleChat);
 */
async function handleChat(req, res) {
  try {
    const { message, session_id: sessionId } = req.body;
    const userId = req.user ? req.user.id : (req.body.user_id || null); 

    if (!message || !sessionId) {
      return res.status(400).json({ success: false, message: 'message and session_id are required' });
    }

    await ensureSession(sessionId, userId);

    const messageType = classifyMessage(message);
    let botReply;
    let isMath = false;
    let contextKeywordsForLog = null;

    // ── 1. Math check runs FIRST, regardless of question/statement.
    const { isMath: mathDetected, expression } = detectMath(message);
    isMath = mathDetected;

    // ── 2. Is there a pending "teach me the answer" question waiting
    //    on this session? Only statements resolve it.
    const pending = messageType === 'statement' ? await findPendingQuestion(sessionId) : null;

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
    } else if (pending) {
      await resolvePendingQuestion(pending.id, pending.question_text, message, userId);
      const flavor = await getRandomScript('general');
      botReply = `Thanks — I've learned that! 🎓${flavor ? ' ' + flavor : ''}`;
    } else if (detectGreeting(message)) {
      const flavor = await getRandomScript('greeting');
      botReply = flavor || "Hey there! 👋 How can I help you today?";
    } else if (messageType === 'question') {
      const keywords = extractKeywords(message, stopwordSet);

      // Does this look like a follow-up ("what about Kilimani?") to the
      // most recent question in this session? If so, merge keyword sets
      // so the lookup/search below has the missing context.
      const { effectiveKeywords, effectiveQueryText, usedContext } =
        await contextEngine.resolveWithContext(sessionId, message, keywords);

      const best = await findBestAnswer(effectiveKeywords);

      if (best) {
        // Fast path: already known, either seeded/taught or a
        // previously cached web search answer.
        await incrementHitCount(best.id);
        const flavor = await getRandomScript('general');
        botReply = `${best.answer_text}${flavor ? '\n\n💡 ' + flavor : ''}`;
      } else {
        // Not in the knowledge base — try searching the web before
        // giving up and asking the user to teach it. Use the
        // context-enriched query text/keywords when this was a
        // follow-up, so "what about Kilimani?" actually searches for
        // something meaningful instead of just "Kilimani".
        const searchQuery = usedContext ? effectiveQueryText : message;
        const webResult = await tryWebSearch(sessionId, userId, searchQuery);

        if (webResult) {
          botReply = formatWebAnswer(webResult);
          await cacheWebAnswer(searchQuery, webResult, effectiveKeywords);
        } else {
          // Store the enriched text (not just the raw follow-up) as
          // question_text, since resolvePendingQuestion re-extracts
          // keywords from question_text later — without this, a
          // follow-up's context would be lost the moment it's taught.
          await createPendingQuestion(sessionId, userId, searchQuery, effectiveKeywords);
          botReply = "I don't know that one yet, and I couldn't find it online either — can you tell me the answer? I'll remember it for next time!";
        }
      }

      // Store THIS message's own keywords (not the merged set) so the
      // next follow-up in the chain anchors off what was actually
      // typed, while still inheriting accumulated context via the
      // merge logic in contextEngine.
      contextKeywordsForLog = keywords;
    } else {
      // Generic small talk: not math, not a pending answer, not a
      // greeting, not classified as a question either.
      const flavor = await getRandomScript('idle');
      botReply = flavor || "Got it, thanks for letting me know!";
    }

    await logChat({ sessionId, userId, message, messageType, isMath, botReply, keywords: contextKeywordsForLog });

    return res.json({ success: true, reply: botReply, type: messageType, is_math: isMath });
  } catch (err) {
    console.error('AI chat error:', err);
    return res.status(500).json({ success: false, message: 'Something went wrong processing that.' });
  }
}

module.exports = { init, handleChat };