/*
 * Adds the access headers the user set for a zero-trust proxy to the server's
 * own fetch and XMLHttpRequest calls. Both apps read this file from the bundle,
 * put the configuration ({ origin, headers }, as JSON) in place of the
 * placeholder on its last line, and run it at document start in the server's
 * origin:
 *
 *   iOS     ios/App/App/TrekAccess.swift  (WKUserScript, main frame only)
 *   Android android/.../access/TrekAccess.kt (WebViewCompat.addDocumentStartJavaScript)
 *
 * A header the page sets itself is never overwritten, and nothing goes to any
 * other origin (map tiles, link previews, a plugin's own host).
 */
(function (config) {
  'use strict';
  if (!config || !Array.isArray(config.headers) || !config.headers.length) return;
  if (typeof location === 'undefined' || location.origin !== config.origin) return;
  var marker = typeof Symbol === 'function' ? Symbol.for('trek.accessHeaders') : '__trekAccessHeaders';
  if (window[marker]) return;
  Object.defineProperty(window, marker, { value: true });

  var headers = config.headers.filter(function (h) {
    return h && typeof h.name === 'string' && typeof h.value === 'string';
  });

  function sameOrigin(url) {
    try {
      return new URL(String(url), location.href).origin === config.origin;
    } catch {
      return false;
    }
  }

  var originalFetch = window.fetch;
  if (typeof originalFetch === 'function') {
    window.fetch = function (input, init) {
      var url = input && typeof input === 'object' && 'url' in input ? input.url : input;
      if (!sameOrigin(url)) return originalFetch.call(window, input, init);
      var source = init && init.headers ? init.headers : input && typeof input === 'object' && input.headers;
      var merged = new Headers(source || undefined);
      headers.forEach(function (h) {
        if (!merged.has(h.name)) merged.set(h.name, h.value);
      });
      return originalFetch.call(window, input, Object.assign({}, init, { headers: merged }));
    };
  }

  var XHR = window.XMLHttpRequest;
  if (typeof XHR === 'function') {
    var proto = XHR.prototype;
    var open = proto.open;
    var send = proto.send;
    var setRequestHeader = proto.setRequestHeader;
    var state = new WeakMap();
    proto.open = function (method, url) {
      state.set(this, { same: sameOrigin(url), set: {} });
      return open.apply(this, arguments);
    };
    proto.setRequestHeader = function (name) {
      var s = state.get(this);
      if (s) s.set[String(name).toLowerCase()] = true;
      return setRequestHeader.apply(this, arguments);
    };
    proto.send = function () {
      var s = state.get(this);
      if (s && s.same) {
        for (var i = 0; i < headers.length; i++) {
          if (!s.set[headers[i].name.toLowerCase()]) setRequestHeader.call(this, headers[i].name, headers[i].value);
        }
      }
      return send.apply(this, arguments);
    };
  }
})(TREK_ACCESS_CONFIG);
