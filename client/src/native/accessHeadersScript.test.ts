import { beforeAll, describe, expect, it, vi } from 'vitest';
import SOURCE from '../../native-shell/static/access-headers.js?raw';

/**
 * The script both apps inject into the server's pages
 * (native-shell/static/access-headers.js), run here the way they run it: the
 * file's text with the configuration appended as the call's argument.
 */

/** The placeholder the apps replace with the configuration, once and only once. */
const PLACEHOLDER = 'TREK_ACCESS_CONFIG';

function inject(config: unknown): void {
  // Indirect eval: the script runs in the global scope, as a WebView runs it.
  (0, eval)(SOURCE.replace(PLACEHOLDER, JSON.stringify(config)));
}

const fetchMock = vi.fn((_input: RequestInfo | URL, _init?: RequestInit) => Promise.resolve(new Response('{}')));
const sentHeaders: Array<Record<string, string>> = [];

beforeAll(() => {
  window.fetch = fetchMock as typeof window.fetch;
  // A stand-in that records what reaches setRequestHeader and sends nothing.
  class RecordingXhr {
    headers: Record<string, string> = {};
    open(_method: string, _url: string): void {}
    setRequestHeader(name: string, value: string): void {
      this.headers[name] = value;
    }
    send(): void {
      sentHeaders.push(this.headers);
    }
  }
  // The environment's XMLHttpRequest is msw's read-only wrapper; replace the property itself.
  Object.defineProperty(window, 'XMLHttpRequest', { value: RecordingXhr, configurable: true, writable: true });
  // Does nothing for another origin or an empty list.
  inject({ origin: 'https://elsewhere.example', headers: [{ name: 'X-No', value: '1' }] });
  inject({ origin: window.location.origin, headers: [] });
  inject({
    origin: window.location.origin,
    headers: [
      { name: 'CF-Access-Client-Id', value: 'id.access' },
      { name: 'CF-Access-Client-Secret', value: 'secret' },
    ],
  });
  // A second injection (a reload that kept the window) adds nothing twice.
  inject({ origin: window.location.origin, headers: [{ name: 'X-Twice', value: '1' }] });
});

function last<T>(items: T[]): T | undefined {
  return items[items.length - 1];
}

function lastFetchHeaders(): Headers {
  const init = last(fetchMock.mock.calls)?.[1];
  return new Headers(init?.headers);
}

describe('access-headers.js: the file the apps read', () => {
  it('names the placeholder exactly once, on the call', () => {
    expect(SOURCE.split(PLACEHOLDER)).toHaveLength(2);
    expect(SOURCE.trimEnd().endsWith(`})(${PLACEHOLDER});`)).toBe(true);
  });
});

describe('access-headers.js: fetch', () => {
  it('adds the headers to a same-origin request', async () => {
    await window.fetch('/api/trips');
    const headers = lastFetchHeaders();
    expect(headers.get('CF-Access-Client-Id')).toBe('id.access');
    expect(headers.get('CF-Access-Client-Secret')).toBe('secret');
    expect(headers.has('X-No')).toBe(false);
    expect(headers.has('X-Twice')).toBe(false);
  });

  it('keeps the request own headers, and never overwrites one it set', async () => {
    await window.fetch(`${window.location.origin}/api/x`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Access-Client-Id': 'page' },
      body: '{}',
    });
    const [, init] = last(fetchMock.mock.calls) ?? [];
    expect(init?.method).toBe('POST');
    expect(init?.body).toBe('{}');
    const headers = lastFetchHeaders();
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(headers.get('CF-Access-Client-Id')).toBe('page');
    expect(headers.get('CF-Access-Client-Secret')).toBe('secret');
  });

  it('reads the headers of a Request passed without init', async () => {
    await window.fetch(new Request(`${window.location.origin}/api/y`, { headers: { 'X-Socket-Id': 's1' } }));
    const headers = lastFetchHeaders();
    expect(headers.get('X-Socket-Id')).toBe('s1');
    expect(headers.get('CF-Access-Client-Secret')).toBe('secret');
  });

  it('sends nothing extra to another origin', async () => {
    await window.fetch('https://tiles.example.com/1/2/3.png', { mode: 'no-cors' });
    const [input, init] = last(fetchMock.mock.calls) ?? [];
    expect(input).toBe('https://tiles.example.com/1/2/3.png');
    expect(init).toEqual({ mode: 'no-cors' });
  });
});

describe('access-headers.js: XMLHttpRequest', () => {
  it('adds the headers to a same-origin request, after the page own', () => {
    const xhr = new window.XMLHttpRequest();
    xhr.open('PUT', '/api/trips/1');
    xhr.setRequestHeader('cf-access-client-id', 'page');
    xhr.send('{}');
    expect(last(sentHeaders)).toEqual({ 'cf-access-client-id': 'page', 'CF-Access-Client-Secret': 'secret' });
  });

  it('adds nothing for another origin', () => {
    const xhr = new window.XMLHttpRequest();
    xhr.open('GET', 'https://api.example.org/x');
    xhr.send();
    expect(last(sentHeaders)).toEqual({});
  });
});
