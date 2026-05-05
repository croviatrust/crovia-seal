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
import { chatgpt, claude, gemini, perplexity } from './hosts';

const host = window.location.hostname;

if (host === 'chatgpt.com' || host === 'chat.openai.com') {
  attachDetector(chatgpt);
} else if (host === 'claude.ai') {
  attachDetector(claude);
} else if (host === 'gemini.google.com') {
  attachDetector(gemini);
} else if (host === 'www.perplexity.ai' || host === 'perplexity.ai') {
  attachDetector(perplexity);
} else {
  // eslint-disable-next-line no-console
  console.log('[crovia-seal] content script loaded on', host, '(no detector for this host)');
}
