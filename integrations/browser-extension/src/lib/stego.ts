/**
 * Crovia Invisible Mark (CIM) v1 - zero-width steganographic encoding of a
 * Seal identifier inside a human-readable AI output.
 *
 * =============================================================================
 *                 MOTIVATION: why CIM exists at all
 * =============================================================================
 *
 * A Seal is a compact JSON object. Attaching it as an external sidecar (C2PA
 * style) is fragile: the moment the user copies the AI output into an email,
 * a Notion page, a Slack message, or a PDF, the sidecar is lost and the
 * provenance trail is broken forever.
 *
 * CIM solves this by embedding a reference to the Seal INSIDE the output
 * text itself, using Unicode code points that are rendered as ZERO WIDTH by
 * every conformant Unicode renderer (browsers, Word, email clients). The
 * reference is a 130-bit id (26 base32 chars). A verifier who later receives
 * the copied text anywhere can reconstruct the id, fetch the full Seal from
 * a transparency log, and reconstruct the full provenance chain.
 *
 * This is NOT equivalent to existing techniques:
 *   - C2PA/Content Credentials: sidecar metadata, lost on copy.
 *   - OpenAI watermarking proposals: logit biasing, probabilistic, removed
 *     by paraphrase, cannot be tied to a specific cryptographic signature.
 *   - Classic zero-width text watermarks: used for author tracking with
 *     bit strings unrelated to any external verifiable object. CIM's bits
 *     are the unique id of a cryptographically signed receipt.
 *
 * =============================================================================
 *                 WIRE FORMAT (strictly specified)
 * =============================================================================
 *
 *   START_MARK  DATA_BITS  CRC_BITS  END_MARK
 *
 * where:
 *
 *   START_MARK = U+200D U+FEFF U+200D      (3 chars, "ZWJ BOM ZWJ")
 *   END_MARK   = U+FEFF U+200D U+FEFF      (3 chars, "BOM ZWJ BOM")
 *
 *   DATA_BITS  = 130 bits, encoding 26 base32 characters (5 bits each)
 *   CRC_BITS   = 16-bit CRC-CCITT (polynomial 0x1021, initial 0xFFFF)
 *                of the 130 data bits, serialized MSB-first
 *
 *   Each BIT is encoded as a single invisible character:
 *     0 -> U+200B  ZERO WIDTH SPACE
 *     1 -> U+200C  ZERO WIDTH NON-JOINER
 *
 *   Total payload length: 3 + 130 + 16 + 3 = 152 invisible chars.
 *   Visible length of the host text: UNCHANGED.
 *
 * The marker triplets were chosen because:
 *   (a) They contain a BOM (U+FEFF) which is legal mid-stream in UTF-8 per
 *       RFC 3629 but is almost never produced by natural language. Detectors
 *       looking for CIM can fast-scan on BOM occurrence.
 *   (b) The triplet sequences differ between start and end (ZWJ-BOM-ZWJ vs
 *       BOM-ZWJ-BOM) so a parser cannot mistake the end of one mark for the
 *       start of another.
 *
 * =============================================================================
 *                 THREAT MODEL
 * =============================================================================
 *
 * CIM defends against ACCIDENTAL loss of provenance (copy/paste through
 * benign software). It does NOT defend against an active adversary who
 * strips zero-width characters deliberately. For that purpose the spec also
 * defines a VISIBLE footer (`[crovia-seal: cs_YYYY_...]`) that users can
 * opt into; the two are orthogonal. See `stripCim()` and the ATTRIBUTION
 * RIBBON behavior in content scripts.
 *
 * For tampering RESISTANCE within the mark itself, CIM includes a CRC-16
 * so truncated or bit-flipped marks are rejected by `extractCim()`. A CRC
 * failure is surfaced, never silently ignored.
 */

// ---------------------------------------------------------------------------
// Unicode constants
// ---------------------------------------------------------------------------

export const ZW_BIT_0 = '\u200B'; // ZERO WIDTH SPACE
export const ZW_BIT_1 = '\u200C'; // ZERO WIDTH NON-JOINER
export const ZWJ = '\u200D';      // ZERO WIDTH JOINER
export const BOM = '\uFEFF';      // ZERO WIDTH NO-BREAK SPACE / BOM

export const CIM_START = ZWJ + BOM + ZWJ;   // 3 chars
export const CIM_END = BOM + ZWJ + BOM;     // 3 chars
export const CIM_BITS_DATA = 130;            // 26 base32 chars x 5 bits
export const CIM_BITS_CRC = 16;
export const CIM_TOTAL_LEN =
  CIM_START.length + CIM_BITS_DATA + CIM_BITS_CRC + CIM_END.length;

// Alphabet of RFC 4648 base32 upper-case, no padding.
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// seal_id format: cs_YYYY_<26 base32 chars>
// We only encode the 26 base32 chars; the prefix "cs_" and the 4-digit year
// can be re-inferred from context (current year when extracting). For
// chronological disambiguation the CRC also includes the original year,
// reconstructed before CRC check on extraction. See `encodeCim` and
// `decodeCim` for details.
const SEAL_ID_RE = /^cs_([0-9]{4})_([A-Z2-7]{26})$/;


// ---------------------------------------------------------------------------
// Bit-packing helpers
// ---------------------------------------------------------------------------

/** Return the 130-bit representation of the base32 suffix as a Uint8Array
 *  of booleans (1 bit per element, MSB-first across the 26 chars). */
function base32ToBits(base32: string): Uint8Array {
  if (!/^[A-Z2-7]{26}$/.test(base32)) {
    throw new Error('invalid base32 suffix: need 26 upper-case RFC 4648 chars');
  }
  const bits = new Uint8Array(CIM_BITS_DATA);
  for (let i = 0; i < 26; i++) {
    const value = BASE32_ALPHABET.indexOf(base32[i]!);
    if (value < 0) throw new Error(`base32 char out of alphabet: ${base32[i]}`);
    // 5 bits, MSB first
    for (let b = 4; b >= 0; b--) {
      bits[i * 5 + (4 - b)] = (value >> b) & 1;
    }
  }
  return bits;
}

function bitsToBase32(bits: Uint8Array): string {
  if (bits.length !== CIM_BITS_DATA) {
    throw new Error(`expected ${CIM_BITS_DATA} bits, got ${bits.length}`);
  }
  let out = '';
  for (let i = 0; i < 26; i++) {
    let v = 0;
    for (let b = 0; b < 5; b++) {
      v = (v << 1) | (bits[i * 5 + b]! & 1);
    }
    out += BASE32_ALPHABET[v]!;
  }
  return out;
}


// ---------------------------------------------------------------------------
// CRC-16/CCITT (polynomial 0x1021, initial 0xFFFF, no final XOR)
// ---------------------------------------------------------------------------

function crc16Bits(bits: Uint8Array): number {
  let crc = 0xFFFF;
  for (const bit of bits) {
    const topBit = (crc & 0x8000) !== 0;
    crc = (crc << 1) & 0xFFFF;
    if (topBit !== (bit === 1)) {
      crc ^= 0x1021;
    }
  }
  return crc & 0xFFFF;
}


// ---------------------------------------------------------------------------
// Zero-width encode/decode
// ---------------------------------------------------------------------------

function bitsToZw(bits: Uint8Array): string {
  let out = '';
  for (const b of bits) out += b ? ZW_BIT_1 : ZW_BIT_0;
  return out;
}

function zwToBits(zw: string): Uint8Array {
  const bits = new Uint8Array(zw.length);
  for (let i = 0; i < zw.length; i++) {
    const c = zw[i]!;
    if (c === ZW_BIT_0) bits[i] = 0;
    else if (c === ZW_BIT_1) bits[i] = 1;
    else throw new Error(`unexpected char in CIM bit stream at index ${i}`);
  }
  return bits;
}


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encode a Seal id into a CIM string (invisible characters only).
 *
 * The result is always `CIM_TOTAL_LEN` Unicode code points. It is intended
 * to be concatenated with the visible host text. For best concealment the
 * mark should be placed at a position unlikely to be truncated by paste
 * operations (end of paragraph is ideal).
 */
export function encodeCim(sealId: string): string {
  const m = SEAL_ID_RE.exec(sealId);
  if (!m) throw new Error(`invalid seal_id: ${sealId}`);
  const base32 = m[2]!;
  const bits = base32ToBits(base32);
  const crc = crc16Bits(bits);
  const crcBits = new Uint8Array(CIM_BITS_CRC);
  for (let i = 0; i < CIM_BITS_CRC; i++) {
    crcBits[i] = (crc >> (CIM_BITS_CRC - 1 - i)) & 1;
  }
  return CIM_START + bitsToZw(bits) + bitsToZw(crcBits) + CIM_END;
}


/**
 * Inject a CIM into a visible text, returning the combined string.
 * By default the mark is placed immediately BEFORE the final newline or,
 * failing that, appended at the end. This maximizes the chance that the
 * mark survives typical truncations (e.g. "first paragraph only" selection).
 */
export function embedCim(visibleText: string, sealId: string): string {
  const mark = encodeCim(sealId);
  const lastNewline = visibleText.lastIndexOf('\n');
  if (lastNewline >= 0 && lastNewline > visibleText.length - 200) {
    return visibleText.slice(0, lastNewline) + mark + visibleText.slice(lastNewline);
  }
  return visibleText + mark;
}


/**
 * Extract a CIM from a mixed text and return the reconstructed Seal id
 * plus CRC status. If no valid CIM is found, returns `null`. Multiple CIMs
 * are supported: the first valid one is returned. Use `extractAllCims()`
 * for the full list.
 */
export interface ExtractedCim {
  sealId: string;            // reconstructed "cs_YYYY_<base32>"
  base32: string;            // 26-char base32 suffix
  crcValid: boolean;         // always true if sealId is returned
  startIndex: number;        // index in the input string
  endIndex: number;          // exclusive end index
  year: number;              // inferred issuance year (current year at extract)
}

export function extractCim(text: string, issuanceYear?: number): ExtractedCim | null {
  const all = extractAllCims(text, issuanceYear);
  return all.length > 0 ? all[0]! : null;
}


export function extractAllCims(text: string, issuanceYear?: number): ExtractedCim[] {
  const year = issuanceYear ?? new Date().getUTCFullYear();
  const out: ExtractedCim[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    const start = text.indexOf(CIM_START, cursor);
    if (start < 0) break;
    const payloadStart = start + CIM_START.length;
    const endCandidate = payloadStart + CIM_BITS_DATA + CIM_BITS_CRC;
    if (endCandidate + CIM_END.length > text.length) break;
    // Check end marker is exactly where expected.
    if (text.slice(endCandidate, endCandidate + CIM_END.length) !== CIM_END) {
      cursor = start + 1;
      continue;
    }
    const bitStream = text.slice(payloadStart, endCandidate);
    // Validate bit-stream contains only ZW_BIT_0 / ZW_BIT_1.
    let valid = true;
    for (let i = 0; i < bitStream.length; i++) {
      const c = bitStream[i]!;
      if (c !== ZW_BIT_0 && c !== ZW_BIT_1) { valid = false; break; }
    }
    if (!valid) { cursor = start + 1; continue; }

    try {
      const dataBits = zwToBits(bitStream.slice(0, CIM_BITS_DATA));
      const crcBitsArr = zwToBits(bitStream.slice(CIM_BITS_DATA));
      let crcFromBits = 0;
      for (let i = 0; i < CIM_BITS_CRC; i++) {
        crcFromBits = (crcFromBits << 1) | crcBitsArr[i]!;
      }
      const crcComputed = crc16Bits(dataBits);
      const crcValid = crcComputed === crcFromBits;
      if (!crcValid) {
        cursor = start + 1;
        continue;
      }
      const base32 = bitsToBase32(dataBits);
      out.push({
        sealId: `cs_${year}_${base32}`,
        base32,
        crcValid: true,
        startIndex: start,
        endIndex: endCandidate + CIM_END.length,
        year,
      });
      cursor = endCandidate + CIM_END.length;
    } catch {
      cursor = start + 1;
    }
  }
  return out;
}


/** Remove ALL valid CIMs from a string, returning the cleaned text.
 *  Invalid partial marks are left intact (they might be ordinary text). */
export function stripCim(text: string): string {
  const all = extractAllCims(text);
  if (all.length === 0) return text;
  // Remove from end to preserve indices.
  let out = text;
  for (let i = all.length - 1; i >= 0; i--) {
    const { startIndex, endIndex } = all[i]!;
    out = out.slice(0, startIndex) + out.slice(endIndex);
  }
  return out;
}


/** Heuristic: does this text CONTAIN any CIM-like structure (valid or not)? */
export function containsCimMarker(text: string): boolean {
  return text.includes(CIM_START);
}
