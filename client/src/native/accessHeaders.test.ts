import { describe, expect, it } from 'vitest';
import {
  MAX_ACCESS_HEADERS,
  MAX_ACCESS_HEADER_VALUE,
  MAX_LOGIN_HOSTS,
  isReservedHeader,
  normalizeLoginHost,
  parseAccessHeaders,
  validateAccessHeaders,
  validateLoginHosts,
} from './accessHeaders';

describe('validateAccessHeaders', () => {
  it('trims the rows and drops the empty ones', () => {
    const result = validateAccessHeaders([
      { name: ' CF-Access-Client-Id ', value: ' abc.access ' },
      { name: '', value: '' },
      { name: 'CF-Access-Client-Secret', value: 's3cr3t' },
    ]);
    expect(result).toEqual({
      ok: true,
      headers: [
        { name: 'CF-Access-Client-Id', value: 'abc.access' },
        { name: 'CF-Access-Client-Secret', value: 's3cr3t' },
      ],
    });
  });

  it('accepts no headers at all', () => {
    expect(validateAccessHeaders([])).toEqual({ ok: true, headers: [] });
  });

  it('refuses a name that is not a token', () => {
    expect(validateAccessHeaders([{ name: 'Bad Name', value: 'x' }])).toEqual({ ok: false, problem: 'name', index: 0 });
    expect(validateAccessHeaders([{ name: '', value: 'x' }])).toEqual({ ok: false, problem: 'name', index: 0 });
    expect(validateAccessHeaders([{ name: 'X:Y', value: 'x' }])).toMatchObject({ problem: 'name' });
  });

  it('refuses names the browser or TREK own', () => {
    for (const name of [
      'Cookie',
      'host',
      'Origin',
      'Sec-Fetch-Mode',
      'Proxy-Authorization',
      'X-Idempotency-Key',
      'X-Socket-Id',
    ]) {
      expect(validateAccessHeaders([{ name, value: 'x' }])).toEqual({ ok: false, problem: 'reserved', index: 0 });
    }
  });

  it('keeps Authorization, which bearer-token proxies need', () => {
    expect(validateAccessHeaders([{ name: 'Authorization', value: 'Bearer t' }]).ok).toBe(true);
  });

  it('refuses an empty, oversized or multi-line value', () => {
    expect(validateAccessHeaders([{ name: 'X-A', value: ' ' }])).toEqual({ ok: false, problem: 'value', index: 0 });
    expect(validateAccessHeaders([{ name: 'X-A', value: 'a\r\nX-Evil: 1' }])).toMatchObject({ problem: 'value' });
    expect(validateAccessHeaders([{ name: 'X-A', value: 'a\u0000' }])).toMatchObject({ problem: 'value' });
    expect(validateAccessHeaders([{ name: 'X-A', value: 'x'.repeat(MAX_ACCESS_HEADER_VALUE + 1) }])).toMatchObject({
      problem: 'value',
    });
    expect(validateAccessHeaders([{ name: 'X-A', value: 'tab\tinside' }]).ok).toBe(true);
  });

  it('refuses the same name twice, in any case', () => {
    expect(
      validateAccessHeaders([
        { name: 'X-Token', value: '1' },
        { name: 'x-token', value: '2' },
      ])
    ).toEqual({ ok: false, problem: 'duplicate', index: 1 });
  });

  it('refuses more than the limit', () => {
    const rows = Array.from({ length: MAX_ACCESS_HEADERS + 1 }, (_, i) => ({ name: `X-H${i}`, value: 'v' }));
    expect(validateAccessHeaders(rows)).toEqual({ ok: false, problem: 'tooMany', index: MAX_ACCESS_HEADERS });
    expect(validateAccessHeaders(rows.slice(0, MAX_ACCESS_HEADERS)).ok).toBe(true);
  });
});

describe('isReservedHeader', () => {
  it('matches whole names and prefixes, ignoring case', () => {
    expect(isReservedHeader('CONTENT-LENGTH')).toBe(true);
    expect(isReservedHeader('access-control-allow-origin')).toBe(true);
    expect(isReservedHeader('CF-Access-Client-Id')).toBe(false);
  });
});

describe('parseAccessHeaders', () => {
  it('keeps only well-formed rows', () => {
    expect(parseAccessHeaders([{ name: 'A', value: '1' }, { name: 2 }, null, 'x', { name: 'B', value: '' }])).toEqual([
      { name: 'A', value: '1' },
      { name: 'B', value: '' },
    ]);
    expect(parseAccessHeaders(undefined)).toEqual([]);
  });
});

describe('login hosts', () => {
  it('normalizes a host, a URL and a wildcard', () => {
    expect(normalizeLoginHost(' MyTeam.CloudflareAccess.com ')).toBe('myteam.cloudflareaccess.com');
    expect(normalizeLoginHost('https://auth.example.com/login?x=1')).toBe('auth.example.com');
    expect(normalizeLoginHost('*.example.com')).toBe('*.example.com');
    expect(normalizeLoginHost('pangolin.local.')).toBe('pangolin.local');
  });

  it('refuses what is not a host, and a wildcard over a whole top-level domain', () => {
    for (const bad of [
      '',
      'exa mple.com',
      '-bad.example.com',
      '*.com',
      '*',
      'ex_ample.com',
      'http://',
      'a'.repeat(64) + '.com',
    ]) {
      expect([bad, normalizeLoginHost(bad)]).toEqual([bad, null]);
    }
  });

  it('splits on commas, spaces and lines, drops repeats and says which entry is wrong', () => {
    expect(validateLoginHosts('a.example.com, b.example.com\nA.example.com')).toEqual({
      ok: true,
      hosts: ['a.example.com', 'b.example.com'],
    });
    expect(validateLoginHosts('')).toEqual({ ok: true, hosts: [] });
    expect(validateLoginHosts('ok.example.com bad_host')).toEqual({ ok: false, problem: 'host', entry: 'bad_host' });
    const many = Array.from({ length: MAX_LOGIN_HOSTS + 1 }, (_, i) => `h${i}.example.com`).join(' ');
    expect(validateLoginHosts(many)).toMatchObject({ ok: false, problem: 'tooMany' });
  });
});
