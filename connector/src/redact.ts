// Redaction runs on the machine before anything is buffered or exported
// (design §9). The server redacts again; neither side relies on the other.

const PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)/g,
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bglpat-[A-Za-z0-9_-]{16,}\b/g,
  /\bsk-(ant-|proj-)?[A-Za-z0-9_-]{16,}\b/g,
  /\bxox[abpors]-[A-Za-z0-9-]{10,}\b/g,
  /\b(agm|agmrt|agmrr|agmcen|agmenr)_[A-Za-z0-9_-]{16,}\b/g,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  /\b(authorization|x-api-key)\s*[:=]\s*(bearer\s+)?[^\s'"]+/gi,
  /\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*[^\s'"]+/gi,
];
const URL_CREDENTIALS = /(:\/\/[^/\s:@]+:)[^@\s/]+@/g;

export const REDACTED = '[REDACTED]';

/** A configured value at least this long is redacted wherever it occurs. */
const SUBSTRING_MIN = 8;

/**
 * A configured value shorter than SUBSTRING_MIN, matched as a whole token
 * (not inside a longer run of letters and digits), so that a short
 * credential is redacted without shredding the words that contain it.
 */
function shortSecret(secret: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9])${secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`, 'g');
}

/**
 * Replaces known secret patterns and the given secret values with
 * [REDACTED]: every occurrence of a value, or every whole-token occurrence
 * of a value shorter than eight characters.
 *
 * @example
 * redact('token is s3cret-value-123', ['s3cret-value-123']); // 'token is [REDACTED]'
 * redact('GATEWAY_TOKEN=t0k, not t0ken', ['t0k']); // 'GATEWAY_TOKEN=[REDACTED], not t0ken'
 */
export function redact(text: string, extraSecrets: string[] = []): string {
  let out = text;
  // Longest first, so that a short value inside a longer one does not
  // leave the rest of the longer one readable.
  for (const secret of [...new Set(extraSecrets)].sort((a, b) => b.length - a.length)) {
    if (!secret || !secret.trim()) continue;
    out = secret.length >= SUBSTRING_MIN ? out.split(secret).join(REDACTED) : out.replace(shortSecret(secret), REDACTED);
  }
  for (const re of PATTERNS) out = out.replace(re, REDACTED);
  return out.replace(URL_CREDENTIALS, `$1${REDACTED}@`);
}

// CSI, OSC and other escape sequences, then remaining C0 controls.
const ANSI = /\u001b\[[0-?]*[ -/]*[@-~]|\u001b\][^\u0007\u001b]*(\u0007|\u001b\\)|\u001b[@-Z\\-_]/g;

/**
 * Text safe to ship: redacted, no terminal control sequences, bounded.
 *
 * @example
 * clean('\u001b[31mOPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwx\u001b[0m', 200); // no key, no escape sequence
 */
export function clean(text: string, max = 4000, extraSecrets: string[] = []): string {
  const stripped = redact(text, extraSecrets).replace(ANSI, '').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '');
  return stripped.length > max ? stripped.slice(0, max) + '…' : stripped;
}

/**
 * Deep redaction of a JSON value's strings.
 *
 * @example
 * redactValue({ env: { TOKEN: 'ghp_abcdefghijklmnopqrstuvwxyz0123' } }); // { env: { TOKEN: '[REDACTED]' } }
 */
export function redactValue(value: unknown, extraSecrets: string[] = []): unknown {
  if (typeof value === 'string') return redact(value, extraSecrets);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, extraSecrets));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactValue(v, extraSecrets);
    return out;
  }
  return value;
}
