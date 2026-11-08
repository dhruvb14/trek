import { Capacitor } from '@capacitor/core';
import {
  MAX_ACCESS_HEADERS,
  validateAccessHeaders,
  type AccessHeader,
  type AccessHeaderProblem,
  type AccessHeadersResult,
} from '../src/native/accessHeaders';
import { toBase64 } from '../src/native/blobBase64';
import { TrekShell, type ClientCertificateInfo } from '../src/native/trekShell';

/**
 * "Access through a proxy" on the connect screen: the headers a zero-trust
 * proxy in front of the server wants (a Cloudflare Access service token, a
 * bearer for oauth2-proxy, …) and the client certificate for a server that
 * asks for one. The binary keeps both and attaches them to that server only
 * (ios/App/App/TrekAccess.swift, android/.../access/TrekAccess.kt).
 */

type Translate = (key: string, params?: Record<string, string>) => string;

export interface AccessSection {
  element: HTMLElement;
  /** Checks the rows, marks the first wrong one and says why; the headers when they are fine. */
  collect(): AccessHeadersResult;
}

export function accessProblemMessage(t: Translate, problem: AccessHeaderProblem, index: number): string {
  const params = { row: String(index + 1) };
  switch (problem) {
    case 'name':
    case 'reserved':
      return t('native.access.errorName', params);
    case 'value':
      return t('native.access.errorValue', params);
    case 'duplicate':
      return t('native.access.errorDuplicate', params);
    case 'tooMany':
      return t('native.access.errorTooMany', params);
  }
}

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const created = document.createElement(tag);
  Object.assign(created, props);
  created.append(...children);
  return created;
}

function textInput(placeholder: string, value: string, secret: boolean): HTMLInputElement {
  const input = node('input', { type: secret ? 'password' : 'text', placeholder, value, spellcheck: false });
  input.setAttribute('autocapitalize', 'off');
  input.setAttribute('autocomplete', 'off');
  input.setAttribute('aria-label', placeholder);
  // A header reads left to right in every language.
  input.dir = 'ltr';
  return input;
}

interface Row {
  element: HTMLElement;
  name: HTMLInputElement;
  value: HTMLInputElement;
}

export function accessSection(t: Translate): AccessSection {
  const rows: Row[] = [];
  const list = node('div', { className: 'access-rows' });
  const error = node('p', { className: 'error' });
  error.setAttribute('role', 'alert');
  const add = node('button', { type: 'button', className: 'linkbtn access-add' }, t('native.access.addHeader'));

  const addRow = (header: AccessHeader = { name: '', value: '' }): Row => {
    const name = textInput(t('native.access.headerName'), header.name, false);
    const value = textInput(t('native.access.headerValue'), header.value, true);
    const remove = node('button', { type: 'button', className: 'access-remove', textContent: '×' });
    remove.setAttribute('aria-label', t('native.access.removeHeader'));
    const element = node(
      'div',
      { className: 'access-row' },
      node('div', { className: 'field' }, name),
      node('div', { className: 'field' }, value),
      remove
    );
    const row: Row = { element, name, value };
    remove.addEventListener('click', () => {
      rows.splice(rows.indexOf(row), 1);
      element.remove();
      add.hidden = false;
    });
    rows.push(row);
    list.append(element);
    add.hidden = rows.length >= MAX_ACCESS_HEADERS;
    return row;
  };
  add.addEventListener('click', () => addRow().name.focus());

  const certificate = certificateBlock(t, error);
  const details = node(
    'details',
    { className: 'access' },
    node('summary', {}, t('native.access.toggle')),
    node(
      'div',
      { className: 'access-body' },
      node('p', { className: 'sub' }, t('native.access.hint')),
      list,
      add,
      certificate.element,
      error
    )
  );

  // What the app holds already, so changing the server keeps it in view.
  TrekShell.getAccess().then(
    ({ headers, certificate: cert }) => {
      for (const header of headers) addRow(header);
      certificate.show(cert);
      if (headers.length || cert) details.open = true;
    },
    () => certificate.show(null)
  );

  return {
    element: details,
    collect() {
      for (const row of rows) row.element.classList.remove('bad');
      error.textContent = '';
      const result = validateAccessHeaders(rows.map((row) => ({ name: row.name.value, value: row.value.value })));
      if ('problem' in result) {
        details.open = true;
        rows[result.index]?.element.classList.add('bad');
        error.textContent = accessProblemMessage(t, result.problem, result.index);
      }
      return result;
    },
  };
}

function certificateBlock(
  t: Translate,
  error: HTMLElement
): { element: HTMLElement; show: (cert: ClientCertificateInfo | null) => void } {
  const android = Capacitor.getPlatform() === 'android';
  const subject = node('span', { className: 'access-subject' });
  subject.dir = 'ltr';
  const choose = node('button', { type: 'button', className: 'demo-link' }, t('native.access.chooseCertificate'));
  const remove = node('button', { type: 'button', className: 'linkbtn' }, t('native.access.removeCertificate'));
  // iOS imports a .p12 into the app's Keychain; Android uses the system's own store.
  const password = textInput(t('native.access.certificatePassword'), '', true);
  const passwordField = node('div', { className: 'field' }, password);
  const file = node('input', { type: 'file', accept: '.p12,.pfx,application/x-pkcs12', hidden: true });

  const show = (cert: ClientCertificateInfo | null): void => {
    subject.textContent = cert?.subject ?? '';
    subject.hidden = !cert;
    remove.hidden = !cert;
    passwordField.hidden = android || Boolean(cert);
    choose.hidden = Boolean(cert);
  };

  choose.addEventListener('click', () => {
    error.textContent = '';
    if (!android) {
      file.click();
      return;
    }
    TrekShell.chooseClientCertificate().then(
      ({ certificate }) => show(certificate),
      () => (error.textContent = t('native.access.errorCertificate'))
    );
  });

  file.addEventListener('change', () => {
    const picked = file.files?.[0];
    file.value = '';
    if (!picked) return;
    toBase64(picked)
      .then((data) => TrekShell.importClientCertificate({ data, password: password.value }))
      .then(
        (cert) => {
          password.value = '';
          show(cert);
        },
        (err: unknown) => {
          const wrongPassword = (err as { code?: string } | null)?.code === 'WRONG_PASSWORD';
          error.textContent = t(wrongPassword ? 'native.access.errorPassword' : 'native.access.errorCertificate');
          if (wrongPassword) password.focus();
        }
      );
  });

  remove.addEventListener('click', () => {
    TrekShell.clearClientCertificate().then(
      () => show(null),
      () => (error.textContent = t('native.access.errorCertificate'))
    );
  });

  const element = node(
    'div',
    { className: 'access-cert' },
    node('span', { className: 'access-label' }, t('native.access.certificate')),
    subject,
    passwordField,
    choose,
    remove,
    file
  );
  return { element, show };
}
