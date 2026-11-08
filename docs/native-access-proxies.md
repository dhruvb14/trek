# Native apps behind zero-trust proxies: custom headers and mTLS

Design note and work list for custom HTTP headers and client certificates (mutual TLS) in the iOS and Android apps. It was written as a GitHub issue; this repository has Issues turned off, so it lives here and in the pull request that implements it. User documentation: `wiki/Native-Apps.md` → *Behind a zero-trust proxy or with a client certificate*.

## Problem

Many self-hosters put TREK behind a zero-trust or identity-aware proxy: Cloudflare Access, Pomerium, Authentik/Authelia outposts, Teleport, oauth2-proxy, or nginx/Traefik requiring a client certificate. A browser gets through with an interactive login or an installed certificate. The native apps can't get through at all:

- The address screen's probe (`GET /api/health/features`) gets the proxy's login page or a 401/403, so it reports **"not TREK"** or **"unreachable"**.
- Machine credentials such as Cloudflare Access **service tokens** (`CF-Access-Client-Id` / `CF-Access-Client-Secret`) or a static bearer header can't be entered anywhere.
- A server that requires **mutual TLS** fails the handshake. Neither WKWebView nor Android WebView presents a client certificate unless the app answers the challenge, and neither app did.

## How the apps talk to the server

Both apps are Capacitor shells (`client/capacitor.config.ts`). The bundled address screen (`client/native-shell/`) probes the server. After that the WebView loads **the server's own origin**, and the UI, its REST calls, `/ws`, uploads and (on Android) the service worker all come from there. "All REST calls" therefore means five request paths:

| # | Path | iOS | Android |
|---|---|---|---|
| 1 | Address-screen probe | was `CapacitorHttp.get` | was `CapacitorHttp.get` |
| 2 | Main-frame document loads | WKWebView | WebView |
| 3 | `fetch`/XHR from the UI (all REST) | WKWebView | WebView (+ service worker) |
| 4 | Subresources and `/ws` | WKWebView | WebView |
| 5 | Native requests to the server | `refreshOfflineCopy` (offline start page), `TrekWatchWriter` / `TrekWatchRefresher` (watch ticks and the silent-push refresh) | none (widgets and the watch get snapshots pushed from JS) |

Map tiles (`TrekTileSchemeHandler`, `tiles/TrekTileStore.kt`) and link previews in the share sheet go to third parties and must **never** carry the headers or the certificate.

## Platform constraints

- **No WebView on either platform has an API that adds a header to every request.**
- **iOS**: `WKURLSchemeHandler` can't take `https`. The options are:
  - main-frame navigations: cancel them in `decidePolicyFor` and reload with the headers;
  - `fetch`/XHR: a document-start `WKUserScript`;
  - subresources and the WebSocket **can't carry custom headers**. They depend on the session cookie the proxy sets after the first authenticated request (Cloudflare Access `CF_Authorization`, Pomerium, oauth2-proxy).
- **Android**: Capacitor 8 injects its bridge with `DOCUMENT_START_SCRIPT`, so the WebView loads every page itself. `shouldInterceptRequest` sees GETs without bodies, so:
  - GETs to the server are re-issued natively with the headers and the WebView's cookies, and `Set-Cookie` is written back;
  - other methods go through the same document-start script (`WebViewCompat.addDocumentStartJavaScript`, restricted to the server origin);
  - the WebSocket again depends on the proxy cookie;
  - a 3xx answer is handed back to the WebView, so a proxy's login redirect is never served under the server's origin.
- **mTLS**:
  - iOS: Capacitor's `handleWKWebViewURLAuthenticationChallenge` plugin hook answers WebView client-certificate challenges (subresources and `/ws` included), and a `URLSessionTaskDelegate` answers them for native requests. A third-party iOS app can't use identities installed through a configuration profile, so the user imports a `.p12`/`.pfx` into the app's Keychain.
  - Android: `onReceivedClientCertRequest` → `ClientCertRequest.proceed()`, using the **system KeyChain** (`KeyChain.choosePrivateKeyAlias`). That covers user-installed and MDM-pushed certificates, and the key never enters the app. Native requests get an `SSLContext` with an `X509ExtendedKeyManager` for that alias.
  - Both: the certificate is offered to the server's host only.
- **System-browser sign-in** (OIDC and passkeys through ASWebAuthenticationSession / Custom Tabs) can't carry the app's headers or Keychain identity. The proxy's browser login or a browser-installed certificate covers it. This is documented, not solved.

## Design

### Binary-only

Everything lives in the app binary and the bundled address screen. The server and its UI are unchanged, so the feature works against every TREK version.

### Configuration

The connect screen has a collapsible **Access through a proxy** section (`client/native-shell/access.ts`):

- **Header rows**: values masked.
- **Client certificate**: iOS imports a `.p12` with its password; Android opens the system chooser.
- **Validation**: `client/src/native/accessHeaders.ts`, repeated in the binaries so a page calling the plugin directly can't get past it:
  - token names;
  - no control characters in values;
  - at most 16 headers, 8 KiB per value;
  - no duplicates;
  - names the browser or TREK own are refused (`Cookie`, `Host`, `Origin`, `Content-*` framing, `Sec-*`, `Proxy-*`, `X-Idempotency-Key`, `X-Socket-Id`, `X-Base-Updated-At`, …).
- **Scope**: the remembered server's origin (scheme, host, port). The probe of a typed address applies them to that host and its same-host redirects. The demo and TREK Cloud flows clear the headers.

### Storage

- iOS: headers as a Keychain generic-password item; the identity as a Keychain identity under a fixed label. Both use `AfterFirstUnlockThisDeviceOnly`, so the background watch refresh can still read them.
- Android: headers AES-GCM-encrypted with a non-exportable AndroidKeyStore key, in private SharedPreferences (`allowBackup` is already off). For the certificate, only the KeyChain alias is stored.

### Plugin surface (`client/src/native/trekShell.ts`)

`getAccess`, `setAccessHeaders`, `importClientCertificate` (iOS), `chooseClientCertificate` (Android), `clearClientCertificate`, `probe`. Capability features: `accessHeaders`, `clientCertificate`.

### One injected script for both WebViews

`client/native-shell/static/access-headers.js` is copied verbatim into `native-dist/` and so ships inside both binaries. It patches `fetch` and `XMLHttpRequest` to add the headers to **same-origin** requests only, and never overwrites one the page set. The binaries put `{ origin, headers }` in place of its `TREK_ACCESS_CONFIG` placeholder. `client/src/native/accessHeadersScript.test.ts` runs the real file.

### Request paths after the change

| # | iOS | Android |
|---|---|---|
| 1 Probe | `TrekShell.probe` → `TrekAccessSession` | `TrekShell.probe` → `TrekAccess.probe` (`HttpURLConnection`) |
| 2 Documents | `TrekNavigationProxy` re-issues with headers | `TrekWebViewClient` → `TrekAccess.intercept` |
| 3 fetch/XHR | document-start `WKUserScript` | GET: interception. Other methods: document-start script. Service worker: `ServiceWorkerClient` |
| 4 Subresources, `/ws` | proxy cookie; mTLS via the plugin hook | GET: interception. `/ws`: proxy cookie. mTLS via `onReceivedClientCertRequest` |
| 5 Native | `TrekAccessSession.shared` for the offline copy and the watch | (no native server calls) |

## Security notes

- Header values are secrets: kept in the Keychain or KeyStore-encrypted, never logged, never sent to another origin. The injected script makes them readable to the server's own page. That's the origin that receives them anyway.
- The certificate is offered only to the configured host. Other hosts get no certificate.
- Nothing is weakened: no TLS-verification bypass, no custom trust store. A private CA still has to be trusted by the OS.

## Work items

- [x] `client/src/native/accessHeaders.ts`: validation + tests
- [x] `client/native-shell/static/access-headers.js` (the apps replace its `TREK_ACCESS_CONFIG` placeholder) + jsdom test; `vite.native.config.js` copies it
- [x] Address screen section (`client/native-shell/access.ts`) + jsdom test; probe through `TrekShell.probe`
- [x] i18n: `native.access.*` in all 28 locales
- [x] `trekShell.ts`: methods, types, features
- [x] iOS: `TrekAccess.swift`, navigation re-issue, user script, challenge hook, plugin methods, offline copy + watch through `TrekAccessSession`
- [x] Android: `access/TrekAccess.kt`, GET + service-worker interception, `onReceivedClientCertRequest`, document-start script, plugin methods, `androidx.webkit` dependency, JVM tests
- [x] Wiki: `wiki/Native-Apps.md`
- [ ] CI build of both native projects (`.github/workflows/native.yml`) green
- [ ] Device verification:

  | Proxy setup | iOS 17 | iOS 18 | iOS 26 | Android 10 | Android 14 | Android 16 |
  |---|---|---|---|---|---|---|
  | Cloudflare Access service token | | | | | | |
  | Pomerium bearer | | | | | | |
  | nginx `ssl_verify_client on` | | | | | | |

  Cover in each run: probe, first load, API writes, uploads, `/ws`, the iOS offline start, the watch refresh, and the service-worker precache.

## Follow-ups

- Headers on the WebSocket upgrade. No WebView API exists; the proxy has to accept the cookie or exempt `/ws`.
- Editing these settings from the server UI's in-app settings (possible through the new capability features).
- Applying header changes made while connected without a reconnect.
