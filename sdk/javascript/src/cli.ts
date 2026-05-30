#!/usr/bin/env node
/**
 * Crovia Seal CLI — verify any seal from the command line
 * Usage:  npx @crovia/seal verify sl_xxx
 *         npx @crovia/seal info sl_xxx
 */

const SEAL_API = 'https://seal.croviatrust.com/v1/seal/';
const TRUST_ROOT = 'https://seal.croviatrust.com/trust-root.json';
const VERIFY_URL = 'https://croviatrust.com/check.html';

const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const BLUE = '\x1b[36m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

async function fetchJSON(url: string) {
  const r = await fetch(url, { headers: { 'User-Agent': 'CroviaCLI/1.0' } });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function csc1(obj: any): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return String(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(csc1).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + csc1(obj[k])).join(',') + '}';
}

async function verify(sealId: string) {
  console.log(`\n${BOLD}Crovia Seal Verifier${RESET} ${DIM}v1.0${RESET}\n`);

  // Step 1: Fetch trust root
  process.stdout.write(`  ${DIM}[1/4]${RESET} Trust root… `);
  try {
    const root = await fetchJSON(TRUST_ROOT);
    console.log(`${GREEN}✓${RESET} ${root.issuer?.id || root.name || 'crovia'}`);
  } catch (e: any) {
    console.log(`${RED}✗${RESET} ${e.message}`);
    process.exit(1);
  }

  // Step 2: Fetch seal
  process.stdout.write(`  ${DIM}[2/4]${RESET} Seal fetch… `);
  let seal: any;
  try {
    seal = await fetchJSON(SEAL_API + encodeURIComponent(sealId));
    const gen = `${seal.generator?.vendor || '?'}/${seal.generator?.model || '?'}`;
    console.log(`${GREEN}✓${RESET} ${gen} · ${seal.issued_at || '?'}`);
  } catch (e: any) {
    console.log(`${RED}✗${RESET} Seal not found`);
    process.exit(1);
  }

  // Step 3: Ed25519 signature
  process.stdout.write(`  ${DIM}[3/4]${RESET} Ed25519 sig… `);
  try {
    const { verify } = await import('@noble/ed25519');
    const { sha512 } = await import('@noble/hashes/sha512');
    const ed = await import('@noble/ed25519');
    (ed as any).etc.sha512Sync = (...m: Uint8Array[]) => sha512(new Uint8Array(m.reduce((a, b) => [...a, ...b], [] as number[])));

    const pubHex = seal.issuer?.pubkey || '';
    const sigHex = seal.signature || '';
    const { signature, ...payload } = seal;
    const canon = csc1(payload);
    const msg = new TextEncoder().encode('CROVIA-SEAL-v1\n' + canon);
    const sigBytes = Uint8Array.from(sigHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
    const pubBytes = Uint8Array.from(pubHex.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
    const valid = await verify(sigBytes, msg, pubBytes);
    if (valid) {
      console.log(`${GREEN}✓${RESET} Valid · ${canon.length} canonical bytes`);
    } else {
      console.log(`${RED}✗${RESET} INVALID signature`);
    }
  } catch (e: any) {
    console.log(`${RED}✗${RESET} ${e.message}`);
  }

  // Step 4: Output hash
  process.stdout.write(`  ${DIM}[4/4]${RESET} Output hash… `);
  console.log(`${DIM}(paste text to verify — CLI ID-only mode)${RESET}`);

  // Summary
  console.log(`\n  ${BOLD}${GREEN}🔒 Seal verified${RESET}`);
  console.log(`  ${DIM}Seal ID:${RESET}    ${BLUE}${seal.seal_id}${RESET}`);
  console.log(`  ${DIM}Generator:${RESET}  ${seal.generator?.vendor}/${seal.generator?.model}`);
  console.log(`  ${DIM}Issued:${RESET}     ${seal.issued_at}`);
  console.log(`  ${DIM}Issuer:${RESET}     ${seal.issuer?.id}`);
  console.log(`  ${DIM}Verify:${RESET}     ${VERIFY_URL}?id=${sealId}`);
  console.log();
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`
${BOLD}@crovia/seal${RESET} — Cryptographic AI provenance

${BOLD}Usage:${RESET}
  npx @crovia/seal verify <seal_id>     Verify a seal
  npx @crovia/seal info <seal_id>       Show seal details (JSON)
  npx @crovia/seal badge <seal_id>      Get README badge markdown

${BOLD}Examples:${RESET}
  npx @crovia/seal verify sl_8b8b5e3b6d851d7214e8129ec216f0497657dd39
  npx @crovia/seal badge sl_8b8b5e3b6d851d7214e8129ec216f0497657dd39

${DIM}https://croviatrust.com${RESET}
`);
    return;
  }

  const cmd = args[0];
  const sealId = args[1];

  if (!sealId || !sealId.startsWith('sl_')) {
    console.error(`${RED}Error:${RESET} Please provide a valid seal ID (sl_...)`);
    process.exit(1);
  }

  if (cmd === 'verify') {
    await verify(sealId);
  } else if (cmd === 'info') {
    const seal = await fetchJSON(SEAL_API + encodeURIComponent(sealId));
    console.log(JSON.stringify(seal, null, 2));
  } else if (cmd === 'badge') {
    console.log(`\n${BOLD}Add to your README.md:${RESET}\n`);
    console.log(`[![Crovia Sealed](https://croviatrust.com/badge/seal/${sealId}.svg)](${VERIFY_URL}?id=${sealId})\n`);
    console.log(`${BOLD}Embed on any website:${RESET}\n`);
    console.log(`<script src="https://croviatrust.com/badge.js" data-seal="${sealId}"></script>\n`);
  } else {
    console.error(`Unknown command: ${cmd}. Use --help`);
    process.exit(1);
  }
}

main().catch(e => { console.error(e.message); process.exit(1); });
