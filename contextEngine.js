// JavaScript source code
// contextEngine.js
// ------------------------------------------------------------
// Short-term conversation memory. Lets follow-up questions like
// "what about Kilimani?" inherit context from the previous
// question in the same session, instead of being answered (or
// failing to be answered) in isolation.
//
// This is a HEURISTIC, not real coreference resolution — it will
// occasionally over-trigger on a short standalone question asked
// soon after an unrelated one. That's the honest tradeoff of doing
// this with rules instead of an LLM.
//
// Expects a mysql2/promise pool to be passed in via init(pool).
// ------------------------------------------------------------

let pool = null;

// How far back "recent" reaches for follow-up matching. Short on
// purpose — a question asked 20 minutes ago is unlikely to still be
// the topic, and a short window reduces false-positive merges.
const CONTEXT_WINDOW_MINUTES = 10;

// Safety cap so a long chain of follow-ups can't grow the merged
// keyword set indefinitely.
const MAX_MERGED_KEYWORDS = 12;

/** Call once at server startup, after your mysql2 pool is created. */
function init(mysqlPool) {
  pool = mysqlPool;
}

/**
 * Fetches the most recent QUESTION-type turn in this session within
 * the context window. Returns { message, keywords_text } or null.
 * Only questions are considered — greetings/statements/small talk
 * aren't useful anchors for "what about X" style follow-ups.
 */
async function getRecentQuestionTurn(sessionId) {
  const [rows] = await pool.query(
    `SELECT message, keywords_text FROM chat_logs
     WHERE session_id = ? AND message_type = 'question'
       AND created_at > (NOW() - INTERVAL ? MINUTE)
     ORDER BY created_at DESC LIMIT 1`,
    [sessionId, CONTEXT_WINDOW_MINUTES]
  );
  return rows.length ? rows[0] : null;
}

// Phrases that near-certainly signal "this continues the last topic".
const FOLLOWUP_STARTERS = /^(what about|how about|and what about|what of|also,?|and\b)/i;

// Bare reference words that only make sense with prior context.
const REFERENCE_WORDS = new Set(['it', 'that', 'this', 'those', 'there', 'they', 'them']);

/**
 * Heuristic: does this message look like it's continuing a prior
 * topic rather than standing on its own? Pure function — doesn't
 * check whether prior context actually exists; call alongside
 * getRecentQuestionTurn and only treat as a follow-up if both are true.
 */
function isFollowUp(message, keywords) {
  const trimmed = (message || '').trim();
  if (!trimmed) return false;

  if (FOLLOWUP_STARTERS.test(trimmed)) return true;

  const wordCount = trimmed.split(/\s+/).length;
  if (wordCount <= 5 && keywords.length <= 2) return true;

  const lower = trimmed.toLowerCase();
  const hasReferenceWord = lower
    .split(/\s+/)
    .some(w => REFERENCE_WORDS.has(w.replace(/[^a-z]/g, '')));
  if (hasReferenceWord && wordCount <= 8) return true;

  return false;
}

/**
 * Merges the current message's keywords with the prior turn's
 * keywords (current message's own keywords take priority / come
 * first), and builds a bag-of-words query string suitable for both
 * knowledge_base lookup and an external web search.
 *
 * Returns { effectiveKeywords, effectiveQueryText, usedContext, priorMessage }.
 */
function buildEffectiveQuery(message, keywords, priorTurn) {
  if (!priorTurn) {
    return { effectiveKeywords: keywords, effectiveQueryText: message, usedContext: false, priorMessage: null };
  }

  const priorKeywords = (priorTurn.keywords_text || '')
    .split(',')
    .map(k => k.trim())
    .filter(Boolean);

  const merged = [...keywords];
  for (const kw of priorKeywords) {
    if (!merged.includes(kw)) merged.push(kw);
  }
  const effectiveKeywords = merged.slice(0, MAX_MERGED_KEYWORDS);

  return {
    effectiveKeywords,
    effectiveQueryText: effectiveKeywords.join(' '),
    usedContext: true,
    priorMessage: priorTurn.message,
  };
}

/**
 * All-in-one helper for aiController: given the current session,
 * message, and its own extracted keywords, returns the context to
 * actually use for lookup/search. If nothing qualifies as a
 * follow-up (or there's no recent question to anchor to), returns
 * the original message/keywords unchanged.
 */
async function resolveWithContext(sessionId, message, keywords) {
  const priorTurn = await getRecentQuestionTurn(sessionId);
  if (!priorTurn || !isFollowUp(message, keywords)) {
    return { effectiveKeywords: keywords, effectiveQueryText: message, usedContext: false, priorMessage: null };
  }
  return buildEffectiveQuery(message, keywords, priorTurn);
}

module.exports = {
  init,
  getRecentQuestionTurn,
  isFollowUp,
  buildEffectiveQuery,
  resolveWithContext,
};