/**
 * The custom headers the app sends to the user's server, for a zero-trust or
 * identity-aware proxy in front of it (a Cloudflare Access service token, a
 * static bearer for Pomerium or oauth2-proxy, …). The address screen collects
 * them and the binary attaches them to the server's origin only
 * (ios/App/App/TrekAccess.swift, android/.../access/TrekAccess.kt). The binary
 * checks the same limits again, so a page calling the plugin directly cannot
 * get past them.
 */

export interface AccessHeader {
  name: string;
  value: string;
}

export const MAX_ACCESS_HEADERS = 16;
export const MAX_ACCESS_HEADER_VALUE = 8192;

/** RFC 9110 field-name: a token. */
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
/** Whether a field value holds CR, LF, NUL or another control character (tab is allowed). */
function hasControlCharacter(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if ((code < 0x20 && code !== 0x09) || code === 0x7f) return true;
  }
  return false;
}

/**
 * Names the browser, the proxy hop or TREK itself own. Setting one would either
 * be ignored by the WebView, break the request, or overwrite what the UI's sync
 * relies on (idempotent replays, echo suppression, conflict checks).
 */
const RESERVED = new Set([
  'accept-encoding',
  'connection',
  'content-length',
  'content-type',
  'cookie',
  'host',
  'keep-alive',
  'origin',
  'referer',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'user-agent',
  'x-base-updated-at',
  'x-idempotency-key',
  'x-socket-id',
]);
const RESERVED_PREFIXES = ['sec-', 'proxy-', 'access-control-'];

export function isReservedHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return RESERVED.has(lower) || RESERVED_PREFIXES.some((prefix) => lower.startsWith(prefix));
}

export type AccessHeaderProblem = 'name' | 'reserved' | 'value' | 'duplicate' | 'tooMany';

export type AccessHeadersResult =
  { ok: true; headers: AccessHeader[] } | { ok: false; problem: AccessHeaderProblem; index: number };

/**
 * Checks the rows as typed. A row left empty on both sides is dropped; names
 * and values are trimmed. `index` points at the first row that is wrong, in the
 * rows as given, so the screen can mark it.
 */
export function validateAccessHeaders(rows: readonly AccessHeader[]): AccessHeadersResult {
  const headers: AccessHeader[] = [];
  const seen = new Set<string>();
  for (const [index, row] of rows.entries()) {
    const name = row.name.trim();
    const value = row.value.trim();
    if (!name && !value) continue;
    if (!TOKEN.test(name)) return { ok: false, problem: 'name', index };
    if (isReservedHeader(name)) return { ok: false, problem: 'reserved', index };
    if (!value || value.length > MAX_ACCESS_HEADER_VALUE || hasControlCharacter(value)) {
      return { ok: false, problem: 'value', index };
    }
    const key = name.toLowerCase();
    if (seen.has(key)) return { ok: false, problem: 'duplicate', index };
    if (headers.length === MAX_ACCESS_HEADERS) return { ok: false, problem: 'tooMany', index };
    seen.add(key);
    headers.push({ name, value });
  }
  return { ok: true, headers };
}

/** Whatever the plugin answered, as rows; anything malformed is left out. */
export function parseAccessHeaders(raw: unknown): AccessHeader[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((item: unknown) => {
    if (typeof item !== 'object' || item === null) return [];
    const { name, value } = item as Record<string, unknown>;
    return typeof name === 'string' && typeof value === 'string' ? [{ name, value }] : [];
  });
}
