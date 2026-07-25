// JavaScript source code
// webSearchEngine.js
// ------------------------------------------------------------
// Pluggable "search the web" fallback for the AI engine.
//
// Default provider: Wikipedia (free, no API key). Good for
// factual/encyclopedic "what is X" / "who is X" questions.
//
// Optional provider: Serper.dev (real Google search results with
// snippets, answer boxes, knowledge graph). Broader coverage —
// handles current events, products, etc. Enable by setting
// SERPER_API_KEY in your environment. Get a key at serper.dev
// (has a free tier, then pay-as-you-go, roughly $0.001/search).
//
// If SERPER_API_KEY is set, it's tried first; Wikipedia is always
// the fallback since it's free and has no rate limit to worry about.
// ------------------------------------------------------------

const axios = require('axios');

const SERPER_API_KEY = process.env.SERPER_API_KEY || null;
const REQUEST_TIMEOUT_MS = 6000;

/**
 * Wikipedia search: finds the best matching page title for the query,
 * then fetches its summary extract.
 * Returns { title, extract, url, provider } or null.
 */
async function searchWikipedia(query) {
  try {
    const searchRes = await axios.get('https://en.wikipedia.org/w/api.php', {
      params: {
        action: 'query',
        list: 'search',
        srsearch: query,
        format: 'json',
        srlimit: 1,
      },
      timeout: REQUEST_TIMEOUT_MS,
    });

    const hit = searchRes.data?.query?.search?.[0];
    if (!hit) return null;

    const title = hit.title;
    const summaryRes = await axios.get(
      `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title)}`,
      { timeout: REQUEST_TIMEOUT_MS }
    );

    const extract = summaryRes.data?.extract;
    if (!extract) return null;

    return {
      title,
      extract,
      url: summaryRes.data?.content_urls?.desktop?.page
        || `https://en.wikipedia.org/wiki/${encodeURIComponent(title)}`,
      provider: 'wikipedia',
    };
  } catch (err) {
    console.error('[webSearchEngine] Wikipedia error:', err.message);
    return null;
  }
}

/**
 * Serper.dev search (Google results). Needs SERPER_API_KEY.
 * Prefers an answer box / knowledge graph if present, otherwise
 * falls back to the first organic result's snippet.
 * Returns { title, extract, url, provider } or null.
 */
async function searchSerper(query) {
  if (!SERPER_API_KEY) return null;

  try {
    const res = await axios.post(
      'https://google.serper.dev/search',
      { q: query },
      {
        headers: { 'X-API-KEY': SERPER_API_KEY, 'Content-Type': 'application/json' },
        timeout: REQUEST_TIMEOUT_MS,
      }
    );

    const data = res.data;

    if (data.answerBox?.answer) {
      return { title: data.answerBox.title || query, extract: data.answerBox.answer, url: data.answerBox.link || null, provider: 'serper' };
    }
    if (data.answerBox?.snippet) {
      return { title: data.answerBox.title || query, extract: data.answerBox.snippet, url: data.answerBox.link || null, provider: 'serper' };
    }
    if (data.knowledgeGraph?.description) {
      return { title: data.knowledgeGraph.title || query, extract: data.knowledgeGraph.description, url: data.knowledgeGraph.descriptionLink || null, provider: 'serper' };
    }
    const top = data.organic?.[0];
    if (top?.snippet) {
      return { title: top.title, extract: top.snippet, url: top.link, provider: 'serper' };
    }
    return null;
  } catch (err) {
    console.error('[webSearchEngine] Serper error:', err.message);
    return null;
  }
}

/**
 * Try the best available provider(s) in order:
 *   1. Serper.dev, if SERPER_API_KEY is configured.
 *   2. Wikipedia — always available, free fallback.
 * Returns { title, extract, url, provider } or null if nothing found.
 */
async function searchWeb(query) {
  if (SERPER_API_KEY) {
    const serperResult = await searchSerper(query);
    if (serperResult) return serperResult;
  }
  return searchWikipedia(query);
}

module.exports = { searchWeb, searchWikipedia, searchSerper };