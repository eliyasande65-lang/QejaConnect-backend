// =========================
// aiController.js
// QejaConnect AI chat handler — knowledge base + quick math +
// teach-me memory + Gemini fallback via @google/genai
// =========================

let dbPromise;
function init(pool) {
  dbPromise = pool;
}

const { GoogleGenAI } = require("@google/genai");
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const SYSTEM_CONTEXT = `You are QejaConnect AI, a friendly assistant for QejaConnect — a Kenyan platform connecting tenants and landlords for housing. Help users navigate the site: finding properties, messaging landlords, booking, rent payments via M-Pesa, and referrals. Keep answers short, clear, and friendly.`;

// =========================
// "teach: question = answer" syntax
// =========================
function parseTeach(message) {
  const match = message.match(/^teach:\s*(.+?)\s*=\s*(.+)$/i);
  if (!match) return null;
  return { trigger: match[1].trim(), answer: match[2].trim() };
}

// =========================
// Safe, narrow arithmetic-only evaluator
// =========================
function tryQuickMath(message) {
  const cleaned = message.trim();
  if (!/^[0-9+\-*/().\s]+$/.test(cleaned) || !/[0-9]/.test(cleaned)) return null;
  try {
    const result = Function(`"use strict"; return (${cleaned})`)();
    if (typeof result === "number" && isFinite(result)) return `${cleaned} = ${result}`;
  } catch (e) {
    // not valid math, ignore
  }
  return null;
}

// =========================
// Knowledge base lookup / save
// =========================
async function findKnowledge(message) {
  const [rows] = await dbPromise.query(
    `SELECT answer FROM ai_knowledge
     WHERE ? LIKE CONCAT('%', trigger_phrase, '%')
     ORDER BY LENGTH(trigger_phrase) DESC LIMIT 1`,
    [message.toLowerCase()]
  );
  return rows.length ? rows[0].answer : null;
}

async function saveKnowledge(trigger, answer) {
  await dbPromise.query(
    `INSERT INTO ai_knowledge (trigger_phrase, answer) VALUES (?, ?)`,
    [trigger.toLowerCase(), answer]
  );
}

// =========================
// Chat log
// =========================
async function logMessage(sessionId, userId, role, message) {
  try {
    await dbPromise.query(
      `INSERT INTO ai_chat_logs (session_id, user_id, role, message) VALUES (?, ?, ?, ?)`,
      [sessionId, userId || null, role, message]
    );
  } catch (err) {
    console.error("[AI LOG]", err.message);
  }
}

// =========================
// Gemini fallback (via @google/genai)
// =========================
async function askGemini(message) {
  const response = await ai.models.generateContent({
    model: "gemini-2.5-flash",
    contents: `${SYSTEM_CONTEXT}\n\nUser: ${message}`,
  });
  return response.text;
}

// =========================
// Main handler — POST /ai/chat
// =========================
async function handleChat(req, res) {
  try {
    const { message, session_id, user_id } = req.body;

    if (!message || !message.trim()) {
      return res.status(400).json({ success: false, reply: "Please type a message." });
    }

    const sessionId = session_id || "anonymous";
    await logMessage(sessionId, user_id, "user", message);

    // 1. Teach-me syntax
    const teach = parseTeach(message);
    if (teach) {
      await saveKnowledge(teach.trigger, teach.answer);
      const reply = `Got it! I'll remember: "${teach.trigger}" → "${teach.answer}"`;
      await logMessage(sessionId, user_id, "ai", reply);
      return res.json({ success: true, reply });
    }

    // 2. Quick math
    const mathResult = tryQuickMath(message);
    if (mathResult) {
      await logMessage(sessionId, user_id, "ai", mathResult);
      return res.json({ success: true, reply: mathResult });
    }

    // 3. Local knowledge base
    const known = await findKnowledge(message);
    if (known) {
      await logMessage(sessionId, user_id, "ai", known);
      return res.json({ success: true, reply: known });
    }

    // 4. Gemini fallback
    const geminiReply = await askGemini(message);
    await logMessage(sessionId, user_id, "ai", geminiReply);
    return res.json({ success: true, reply: geminiReply });

  } catch (err) {
    console.error("[AI CHAT ERROR]", err.message);
    return res.status(500).json({
      success: false,
      reply: "Sorry, I'm having trouble responding right now. Please try again shortly."
    });
  }
}

module.exports = { init, handleChat };