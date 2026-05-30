/**
 * Content-script entry point.
 *
 * Picks the right HostAdapter for the current domain and hands it to the
 * generic detector. Each adapter is a pure data description of DOM
 * selectors; the running machinery lives in `detector-base.ts`.
 *
 * Coverage matrix (see manifest host_permissions):
 *   - ChatGPT       (chatgpt.com, chat.openai.com)
 *   - Claude        (claude.ai)
 *   - Gemini        (gemini.google.com)
 *   - Perplexity    (www.perplexity.ai)
 */
import { attachDetector } from './detector-base';
import { attachPassiveDetector } from './passive-detector';
import { chatgpt, claude, gemini, perplexity } from './hosts';

// eslint-disable-next-line no-console
console.log('[crovia-seal] content script loaded on', window.location.hostname);

const host = window.location.hostname;

function diagSelectors(adapter: { name: string; assistantSelector: string }): void {
  try {
    const selectors = adapter.assistantSelector.split(', ');
    let matched = 0;
    for (const s of selectors) {
      try {
        matched += document.querySelectorAll(s).length;
      } catch { /* invalid selector in this context */ }
    }
    // eslint-disable-next-line no-console
    console.log(`[crovia-seal:${adapter.name}] matched ${matched} element(s) at load time`);
  } catch { /* ignore all errors in diag */ }
}

// 1) ACTIVE SEALER — only on supported AI chat hosts (inject "Seal" button)
if (host === 'chatgpt.com' || host === 'chat.openai.com') {
  diagSelectors(chatgpt);
  attachDetector(chatgpt);
} else if (host === 'claude.ai') {
  diagSelectors(claude);
  attachDetector(claude);
} else if (host === 'gemini.google.com') {
  diagSelectors(gemini);
  attachDetector(gemini);
} else if (host === 'www.perplexity.ai' || host === 'perplexity.ai') {
  diagSelectors(perplexity);
  attachDetector(perplexity);
}

// 2) PASSIVE DETECTOR — runs everywhere (Twitter, news, Reddit, anywhere),
//    finds sealed text via invisible CIM markers and shows a verified badge.
//    This is what makes Crovia Seal recognizable across the entire web.
attachPassiveDetector();
