import { beforeEach, describe, expect, it, vi } from 'vitest';

// FE-NATIVE-ACCESS-001 to FE-NATIVE-ACCESS-006
//
// "Access through a proxy" on the native connect screen (native-shell/access.ts):
// the rows it shows from what the binary holds, the checks it runs before the
// probe, and the certificate flows of each platform, against a mocked plugin.

const shell = vi.hoisted(() => ({
  getAccess: vi.fn(),
  importClientCertificate: vi.fn(),
  chooseClientCertificate: vi.fn(),
  clearClientCertificate: vi.fn(),
}));
const platform = vi.hoisted(() => ({ name: 'ios' }));

vi.mock('../../../src/native/trekShell', () => ({ TrekShell: shell }));
vi.mock('@capacitor/core', () => ({ Capacitor: { getPlatform: () => platform.name } }));

import { accessProblemMessage, accessSection } from '../../../native-shell/access';

const t = (key: string, params: Record<string, string> = {}): string =>
  Object.keys(params).length ? `${key}:${JSON.stringify(params)}` : key;

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

function inputs(root: HTMLElement): HTMLInputElement[] {
  return [...root.querySelectorAll<HTMLInputElement>('.access-row input')];
}

function button(root: HTMLElement, label: string): HTMLButtonElement {
  const found = [...root.querySelectorAll<HTMLButtonElement>('button')].find(
    (b) => b.textContent === label || b.getAttribute('aria-label') === label
  );
  if (!found) throw new Error(`no button ${label}`);
  return found;
}

beforeEach(() => {
  platform.name = 'ios';
  for (const fn of Object.values(shell)) fn.mockReset();
  shell.getAccess.mockResolvedValue({ headers: [], certificate: null });
  document.body.innerHTML = '';
});

describe('native shell: access through a proxy', () => {
  it('FE-NATIVE-ACCESS-001: starts closed and empty without stored access', async () => {
    const section = accessSection(t);
    document.body.append(section.element);
    await flush();
    expect((section.element as HTMLDetailsElement).open).toBe(false);
    expect(inputs(section.element)).toHaveLength(0);
    expect(section.collect()).toEqual({ ok: true, headers: [] });
  });

  it('FE-NATIVE-ACCESS-002: opens on the stored headers and certificate, values masked', async () => {
    shell.getAccess.mockResolvedValue({
      headers: [{ name: 'CF-Access-Client-Id', value: 'id' }],
      certificate: { subject: 'alice' },
    });
    const section = accessSection(t);
    await flush();
    expect((section.element as HTMLDetailsElement).open).toBe(true);
    const [name, value] = inputs(section.element);
    expect(name.value).toBe('CF-Access-Client-Id');
    expect(value.type).toBe('password');
    expect(section.element.querySelector('.access-subject')?.textContent).toBe('alice');
    expect(section.collect()).toEqual({ ok: true, headers: [{ name: 'CF-Access-Client-Id', value: 'id' }] });
  });

  it('FE-NATIVE-ACCESS-003: marks the first wrong row and says which', async () => {
    const section = accessSection(t);
    await flush();
    button(section.element, 'native.access.addHeader').click();
    button(section.element, 'native.access.addHeader').click();
    const [n1, v1, n2, v2] = inputs(section.element);
    n1.value = 'X-Ok';
    v1.value = 'fine';
    n2.value = 'Cookie';
    v2.value = 'nope';
    const result = section.collect();
    expect(result).toEqual({ ok: false, problem: 'reserved', index: 1 });
    expect(section.element.querySelectorAll('.access-row')[1].classList.contains('bad')).toBe(true);
    expect(section.element.querySelector('.error')?.textContent).toBe('native.access.errorName:{"row":"2"}');
    // Removing the row clears the problem.
    (section.element.querySelectorAll('.access-remove')[1] as HTMLButtonElement).click();
    expect(section.collect()).toEqual({ ok: true, headers: [{ name: 'X-Ok', value: 'fine' }] });
  });

  it('FE-NATIVE-ACCESS-004: names each problem with its key', () => {
    expect(accessProblemMessage(t, 'value', 0)).toBe('native.access.errorValue:{"row":"1"}');
    expect(accessProblemMessage(t, 'duplicate', 2)).toBe('native.access.errorDuplicate:{"row":"3"}');
    expect(accessProblemMessage(t, 'tooMany', 16)).toBe('native.access.errorTooMany:{"row":"17"}');
  });

  it('FE-NATIVE-ACCESS-005: iOS imports a .p12 with its password, and says when the password is wrong', async () => {
    const section = accessSection(t);
    await flush();
    const password = section.element.querySelector<HTMLInputElement>('.access-cert input[type=password]');
    const file = section.element.querySelector<HTMLInputElement>('input[type=file]');
    if (!password || !file) throw new Error('missing certificate inputs');
    password.value = 'pw';
    Object.defineProperty(file, 'files', { value: [new Blob(['p12'])], configurable: true });

    shell.importClientCertificate.mockRejectedValueOnce({ code: 'WRONG_PASSWORD' });
    file.dispatchEvent(new Event('change'));
    await vi.waitFor(() =>
      expect(section.element.querySelector('.error')?.textContent).toBe('native.access.errorPassword')
    );
    expect(shell.importClientCertificate).toHaveBeenCalledWith({ data: 'cDEy', password: 'pw' });

    shell.importClientCertificate.mockResolvedValueOnce({ subject: 'device-7' });
    file.dispatchEvent(new Event('change'));
    await vi.waitFor(() => expect(section.element.querySelector('.access-subject')?.textContent).toBe('device-7'));
    expect(password.value).toBe('');

    shell.clearClientCertificate.mockResolvedValueOnce(undefined);
    button(section.element, 'native.access.removeCertificate').click();
    await vi.waitFor(() => expect((section.element.querySelector('.access-subject') as HTMLElement).hidden).toBe(true));
  });

  it('FE-NATIVE-ACCESS-006: Android opens the system chooser and asks for no password', async () => {
    platform.name = 'android';
    shell.chooseClientCertificate.mockResolvedValueOnce({ certificate: { subject: 'bob', expires: '2027-01-01' } });
    const section = accessSection(t);
    await flush();
    const passwordField = section.element.querySelector<HTMLElement>('.access-cert .field');
    expect(passwordField?.hidden).toBe(true);
    button(section.element, 'native.access.chooseCertificate').click();
    await vi.waitFor(() => expect(section.element.querySelector('.access-subject')?.textContent).toBe('bob'));
    expect(shell.importClientCertificate).not.toHaveBeenCalled();
  });
});
