// nlpEngine.js
// ------------------------------------------------------------
// Pure, DB-agnostic NLP helpers. No network / DB calls in here —
// keeps it easy to unit test.
// ------------------------------------------------------------

const nlp = require('compromise');
const { evaluate } = require('mathjs');

// Fallback stopword list, used only if the DB table can't be reached.
// The real list should be loaded from the `stopwords` table at startup
// (see aiController.loadStopwords).
const FALLBACK_STOPWORDS = new Set([
  'he','him','his','she','her','hers','who','whom','whose',
  'when','why','what','where','how','which',
  'is','are','was','were','am','be','been','being',
  'the','a','an','do','does','did','doing',
  'will','would','shall','should','can','could','may','might','must',
  'of','to','in','on','at','for','with','and','or','but','not',
  'this','that','these','those','it','its',
  'i','you','your','yours','we','our','ours',
  'they','their','theirs','me','my','mine','us','them',
  'then','than','so','if','because','as','from','by',
  'about','into','through','during','before','after',
  'above','below','up','down','out','off','over','under',
  'again','further','once','there','here',
  'all','any','both','each','few','more','most','other',
  'some','such','no','nor','only','own','same','too','very',
  'just','please','tell','know','let','also'
]);

const QUESTION_WORDS = [
  'what', 'who', 'whom', 'whose', 'when', 'where', 'why', 'how',
  'which', 'is', 'are', 'was', 'were', 'do', 'does', 'did',
  'can', 'could', 'will', 'would', 'shall', 'should', 'may', 'might'
];

/**
 * Classify a message as a 'question' or 'statement'.
 * Rules (in priority order):
 *   1. Ends with "?"                              -> question
 *   2. Starts with a recognised question word      -> question
 *   3. compromise detects an interrogative sentence -> question
 *   4. Otherwise                                    -> statement
 */
function classifyMessage(rawText) {
  const text = (rawText || '').trim();
  if (!text) return 'statement';

  if (text.endsWith('?')) return 'question';

  const firstWord = text.split(/\s+/)[0].toLowerCase().replace(/[^a-z']/g, '');
  if (QUESTION_WORDS.includes(firstWord)) return 'question';

  try {
    const doc = nlp(text);
    if (doc.questions().found) return 'question';
  } catch (e) {
    // compromise failed to parse — fall through to statement
  }

  return 'statement';
}

/**
 * Extract normalised, de-duplicated keywords from text, excluding stopwords.
 * @param {string} text
 * @param {Set<string>} stopwordSet - lowercase stopwords to exclude
 * @returns {string[]}
 */
function extractKeywords(text, stopwordSet = FALLBACK_STOPWORDS) {
  if (!text) return [];

  const tokens = text
    .toLowerCase()
    .replace(/[^a-z0-9\s']/g, ' ')
    .split(/\s+/)
    .map(w => w.trim())
    .filter(Boolean);

  const seen = new Set();
  const keywords = [];

  for (const token of tokens) {
    if (token.length < 2) continue;           // drop single letters
    if (stopwordSet.has(token)) continue;      // drop stopwords
    if (/^\d+$/.test(token)) continue;         // drop pure numbers (math handles those)
    if (seen.has(token)) continue;
    seen.add(token);
    keywords.push(token);
  }

  return keywords;
}

// Word-form operators people actually type, converted before regex extraction.
const WORD_OPERATORS = [
  [/\bplus\b/g, '+'],
  [/\bminus\b/g, '-'],
  [/\btimes\b/g, '*'],
  [/\bmultiplied by\b/g, '*'],
  [/\bdivided by\b/g, '/'],
  [/\bover\b/g, '/'],
  [/\bpower of\b/g, '^'],
  [/\bsquared\b/g, '^2'],
  [/\bx\b/g, '*'] // "3 x 4"
];

// Matches things like: 12 + 4, 3.5 * (2-1), 10 / 2 + 3
const MATH_EXPRESSION_REGEX =
  /-?\d+(\.\d+)?\s*(\^|\*|\/|\+|-|%)\s*(-?\(?\d)[\d.\s+\-*/^%()]*\d\)?|\(\s*-?\d+(\.\d+)?\s*(\^|\*|\/|\+|-|%)[\d.\s+\-*/^%()]*\)/;

/**
 * Try to find a math expression inside a natural-language question.
 * Returns { isMath: boolean, expression: string|null }
 */
function detectMath(rawText) {
  if (!rawText) return { isMath: false, expression: null };

  let text = rawText.toLowerCase();
  for (const [pattern, replacement] of WORD_OPERATORS) {
    text = text.replace(pattern, replacement);
  }

  const match = text.match(MATH_EXPRESSION_REGEX);
  if (!match) return { isMath: false, expression: null };

  // Trim to only safe math characters before handing to mathjs
  const expression = match[0].replace(/[^0-9.+\-*/^%() ]/g, '').trim();
  if (!expression) return { isMath: false, expression: null };

  return { isMath: true, expression };
}

/**
 * Safely evaluate a math expression string using mathjs.
 * Returns { success: boolean, result: number|null, error?: string }
 */
function evaluateMath(expression) {
  try {
    const result = evaluate(expression);
    if (typeof result !== 'number' || !isFinite(result)) {
      return { success: false, result: null, error: 'non_numeric_result' };
    }
    // round to avoid floating point noise like 0.30000000000000004
    const rounded = Math.round(result * 1e8) / 1e8;
    return { success: true, result: rounded };
  } catch (err) {
    return { success: false, result: null, error: err.message };
  }
}

// Matches a message that IS a greeting (whole message, allowing for
// punctuation/an exclamation, not just contains-a-greeting-word somewhere).
const GREETING_REGEX =
  /^(hi+|hey+|hello+|yo+|sup|howdy|greetings|good\s?morning|good\s?afternoon|good\s?evening|morning|evening)[\s!.,]*$/i;

/**
 * Returns true if the whole message is essentially just a greeting,
 * e.g. "hi", "hey there", "hello!", "good morning".
 */
function detectGreeting(rawText) {
  const text = (rawText || '').trim();
  if (!text) return false;
  // Strip a trailing "there" / "guys" / name so "hey there" still matches.
  const stripped = text.replace(/\b(there|guys|team|everyone)\b/gi, '').trim();
  return GREETING_REGEX.test(stripped);
}

module.exports = {
  classifyMessage,
  extractKeywords,
  detectMath,
  detectGreeting,
  evaluateMath,
  FALLBACK_STOPWORDS
};