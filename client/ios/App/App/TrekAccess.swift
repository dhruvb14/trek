import Foundation
import Security
import WebKit

/// Access to a TREK server that sits behind a zero-trust or identity-aware
/// proxy (Cloudflare Access, Pomerium, oauth2-proxy, an mTLS front end): the
/// custom headers the user set on the address screen and the client
/// certificate they imported (client/native-shell/access.ts).
///
/// Both go to the remembered server only, never to map tiles, link previews or
/// any other host. Where each request path picks them up:
/// - the WebView's main-frame loads: TrekNavigationProxy, through `reissue`;
/// - the UI's fetch and XMLHttpRequest calls: `userScript`
///   (client/native-shell/static/access-headers.js);
/// - the WebView's client-certificate challenges, subresources and /ws
///   included: TrekShellPlugin.handleWKWebViewURLAuthenticationChallenge;
/// - the app's own requests (offline copy, watch, the address screen's probe):
///   TrekAccessSession;
/// - the proxy's own login page, which stays in the WebView when its domain is
///   one of `loginHosts` (TrekShellPlugin.shouldOverrideLoad), behind
///   TrekBridgeOriginGate so that page cannot reach the app's plugins.
///
/// A WKWebView cannot add a header to an image, a script or the WebSocket, so
/// those depend on the session cookie the proxy sets on the first
/// authenticated load (Cloudflare Access's CF_Authorization, for one).
enum TrekAccess {
    struct Header: Codable, Equatable {
        let name: String
        let value: String
    }

    /// The same limits as client/src/native/accessHeaders.ts, held again here so
    /// a page calling the plugin directly cannot get past them.
    static let maxHeaders = 16
    static let maxValueLength = 8192
    private static let tokenCharacters = CharacterSet(
        charactersIn: "!#$%&'*+.^_`|~-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    )

    private static let service = "com.liketrek.trek.access"
    private static let headersAccount = "headers"
    private static let identityLabel = "com.liketrek.trek.client-identity"

    private static let lock = NSLock()
    private static var cachedHeaders: [Header]?

    // MARK: - Headers

    /// The stored headers, read from the Keychain once.
    static var headers: [Header] {
        lock.lock()
        defer { lock.unlock() }
        if let cachedHeaders { return cachedHeaders }
        let loaded = readHeaders()
        cachedHeaders = loaded
        return loaded
    }

    /// Replaces the headers; false when one breaks the limits or the Keychain refused.
    static func setHeaders(_ headers: [Header]) -> Bool {
        guard headers.count <= maxHeaders, headers.allSatisfy(isValid),
              Set(headers.map { $0.name.lowercased() }).count == headers.count else { return false }
        lock.lock()
        defer { lock.unlock() }
        let stored = headers.isEmpty ? deleteHeaders() : writeHeaders(headers)
        if stored { cachedHeaders = headers }
        return stored
    }

    static func isValid(_ header: Header) -> Bool {
        guard !header.name.isEmpty, header.name.unicodeScalars.allSatisfy({ tokenCharacters.contains($0) }),
              !header.value.isEmpty, header.value.utf16.count <= maxValueLength else { return false }
        return header.value.unicodeScalars.allSatisfy { scalar in
            (scalar.value >= 0x20 || scalar.value == 0x09) && scalar.value != 0x7F
        }
    }

    private static var headersQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: headersAccount,
        ]
    }

    private static func readHeaders() -> [Header] {
        var query = headersQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let data = result as? Data,
              let decoded = try? JSONDecoder().decode([Header].self, from: data) else { return [] }
        return decoded.filter(isValid)
    }

    /// Readable after the first unlock, so the watch refresh a silent push wakes
    /// in the background still has them; never restored onto another device.
    private static func writeHeaders(_ headers: [Header]) -> Bool {
        guard let data = try? JSONEncoder().encode(headers) else { return false }
        let fields: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemUpdate(headersQuery as CFDictionary, fields as CFDictionary)
        if status == errSecSuccess { return true }
        guard status == errSecItemNotFound else { return false }
        let add = headersQuery.merging(fields) { $1 }
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess
    }

    private static func deleteHeaders() -> Bool {
        let status = SecItemDelete(headersQuery as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// The request with every stored header it does not set itself.
    static func adding(_ headers: [Header], to request: URLRequest) -> URLRequest {
        var copy = request
        for header in headers where copy.value(forHTTPHeaderField: header.name) == nil {
            copy.setValue(header.value, forHTTPHeaderField: header.name)
        }
        return copy
    }

    /// The request with the headers when it goes to the server; unchanged otherwise.
    static func authorized(_ request: URLRequest) -> URLRequest {
        isServer(request.url) ? adding(headers, to: request) : request
    }

    // MARK: - Scope

    static var serverURL: URL? {
        guard let raw = TrekServerStore.url, let url = URL(string: raw), url.host != nil else { return nil }
        return url
    }

    static func port(_ url: URL) -> Int {
        url.port ?? (url.scheme?.lowercased() == "http" ? 80 : 443)
    }

    static func sameHost(_ a: URL, _ b: URL) -> Bool {
        guard let hostA = a.host?.lowercased(), let hostB = b.host?.lowercased() else { return false }
        return hostA == hostB
    }

    /// Same scheme, host and port: the browser's idea of one origin.
    static func sameOrigin(_ a: URL, _ b: URL) -> Bool {
        a.scheme?.lowercased() == b.scheme?.lowercased() && sameHost(a, b) && port(a) == port(b)
    }

    static func isServer(_ url: URL?) -> Bool {
        guard let url, let server = serverURL else { return false }
        return sameOrigin(url, server)
    }

    /// The origin as `location.origin` spells it, without a default port.
    static func origin(_ url: URL) -> String? {
        guard let scheme = url.scheme?.lowercased(), var host = url.host?.lowercased() else { return nil }
        if host.contains(":") { host = "[\(host)]" }
        let defaultPort = scheme == "http" ? 80 : 443
        return port(url) == defaultPort ? "\(scheme)://\(host)" : "\(scheme)://\(host):\(port(url))"
    }

    // MARK: - WebView

    private static var lastReissue: (url: URL, at: Date)?

    /// A main-frame GET to the server that went out without the headers, ready
    /// to load again with them; nil for every other navigation. A history step
    /// is left alone (loading it anew would add an entry), and the same URL is
    /// never sent round twice within two seconds, should WebKit ever drop the
    /// headers it was given. Main thread only.
    static func reissue(_ action: WKNavigationAction) -> URLRequest? {
        let request = action.request
        let stored = headers
        guard !stored.isEmpty, action.targetFrame?.isMainFrame == true, action.navigationType != .backForward,
              (request.httpMethod ?? "GET").uppercased() == "GET", let url = request.url, isServer(url),
              stored.contains(where: { request.value(forHTTPHeaderField: $0.name) == nil }) else { return nil }
        if let last = lastReissue, last.url == url, Date().timeIntervalSince(last.at) < 2 { return nil }
        lastReissue = (url, Date())
        return adding(stored, to: request)
    }

    /// The document-start script that adds the headers to the UI's own fetch and
    /// XMLHttpRequest calls, or nil without headers or a server.
    static func userScript() -> WKUserScript? {
        let stored = headers
        guard !stored.isEmpty, let server = serverURL, let origin = origin(server),
              let file = Bundle.main.url(forResource: "access-headers", withExtension: "js", subdirectory: "public"),
              let source = try? String(contentsOf: file, encoding: .utf8) else { return nil }
        let config: [String: Any] = [
            "origin": origin,
            "headers": stored.map { ["name": $0.name, "value": $0.value] },
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: config),
              let json = String(data: data, encoding: .utf8) else { return nil }
        let script = source.replacingOccurrences(of: "TREK_ACCESS_CONFIG", with: json)
        return WKUserScript(source: script, injectionTime: .atDocumentStart, forMainFrameOnly: true)
    }

    // MARK: - Sign-in domains

    /// The proxy's sign-in domains (client/src/native/accessHeaders.ts,
    /// validateLoginHosts): a page on one of them stays in the WebView, so the
    /// proxy's login sets its cookie where the UI runs instead of in Safari.
    /// Not secret, so they live in the app's defaults.
    static let maxLoginHosts = 8
    private static let loginHostsKey = "TrekAccessLoginHosts"

    static var loginHosts: [String] {
        (UserDefaults.standard.stringArray(forKey: loginHostsKey) ?? []).filter(isValidLoginHost)
    }

    /// Replaces the domains; false when one is not a host or `*.` and a domain of two labels or more.
    static func setLoginHosts(_ hosts: [String]) -> Bool {
        let lowered = hosts.map { $0.lowercased() }
        guard lowered.count <= maxLoginHosts, lowered.allSatisfy(isValidLoginHost) else { return false }
        if lowered.isEmpty {
            UserDefaults.standard.removeObject(forKey: loginHostsKey)
        } else {
            UserDefaults.standard.set(lowered, forKey: loginHostsKey)
        }
        return true
    }

    static func isValidLoginHost(_ entry: String) -> Bool {
        let wildcard = entry.hasPrefix("*.")
        let host = wildcard ? String(entry.dropFirst(2)) : entry
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard host.count <= 253, labels.count >= (wildcard ? 2 : 1) else { return false }
        return labels.allSatisfy { label in
            (1...63).contains(label.count) && label.first != "-" && label.last != "-"
                && label.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" }
        }
    }

    /// Whether an http(s) URL is on a sign-in domain: the host itself, or a subdomain of a `*.` entry.
    static func isLoginHost(_ url: URL?) -> Bool {
        guard let url, let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = url.host?.lowercased() else { return false }
        return loginHosts.contains { entry in
            entry.hasPrefix("*.") ? host.hasSuffix(String(entry.dropFirst(1))) && host.count > entry.count - 1 : host == entry
        }
    }

    // MARK: - Client certificate

    enum ImportError: Error {
        case wrongPassword
        case invalid
        case keychain
    }

    private static var identityQuery: [String: Any] {
        [kSecClass as String: kSecClassIdentity, kSecAttrLabel as String: identityLabel]
    }

    /// The imported identity (certificate and private key), if any.
    static var identity: SecIdentity? {
        var query = identityQuery
        query[kSecReturnRef as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let result,
              CFGetTypeID(result) == SecIdentityGetTypeID() else { return nil }
        return (result as! SecIdentity)
    }

    /// Imports the first identity of a PKCS#12 file into the app's Keychain, in
    /// place of any earlier one, and returns its subject. iOS reads only files
    /// with modern encryption (AES); a legacy RC2 .p12 fails as `invalid`.
    static func importIdentity(pkcs12 data: Data, password: String) throws -> String {
        var items: CFArray?
        let status = SecPKCS12Import(data as CFData, [kSecImportExportPassphrase as String: password] as CFDictionary, &items)
        if status == errSecAuthFailed { throw ImportError.wrongPassword }
        guard status == errSecSuccess, let entries = items as? [[String: Any]],
              let value = entries.first?[kSecImportItemIdentity as String],
              CFGetTypeID(value as CFTypeRef) == SecIdentityGetTypeID() else { throw ImportError.invalid }
        let imported = value as! SecIdentity
        clearIdentity()
        let add: [String: Any] = [
            kSecValueRef as String: imported,
            kSecAttrLabel as String: identityLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        guard SecItemAdd(add as CFDictionary, nil) == errSecSuccess else { throw ImportError.keychain }
        return subject(of: imported) ?? ""
    }

    static func clearIdentity() {
        SecItemDelete(identityQuery as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassCertificate, kSecAttrLabel as String: identityLabel] as CFDictionary)
        SecItemDelete([kSecClass as String: kSecClassKey, kSecAttrLabel as String: identityLabel] as CFDictionary)
    }

    static func subject(of identity: SecIdentity) -> String? {
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { return nil }
        return SecCertificateCopySubjectSummary(certificate) as String?
    }

    /// What the plugin reports about the certificate, or nil without one.
    static func certificateInfo() -> [String: Any]? {
        guard let stored = identity else { return nil }
        return ["subject": subject(of: stored) ?? ""]
    }

    /// Whether a challenge comes from the remembered server's host and port.
    static func isServerSpace(_ space: URLProtectionSpace) -> Bool {
        guard let server = serverURL else { return false }
        return space.host.lowercased() == server.host?.lowercased() && space.port == port(server)
    }

    /// The answer to a client-certificate challenge, or nil for any other kind.
    /// Only a host `allowed` takes gets the identity; every other one is answered
    /// without a certificate.
    static func clientCertificateAnswer(
        _ challenge: URLAuthenticationChallenge,
        allowed: (URLProtectionSpace) -> Bool
    ) -> (URLSession.AuthChallengeDisposition, URLCredential?)? {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate else { return nil }
        guard allowed(challenge.protectionSpace), let stored = identity else { return (.performDefaultHandling, nil) }
        return (.useCredential, URLCredential(identity: stored, certificates: nil, persistence: .forSession))
    }
}

/// A URLSession that sends the access headers and answers client-certificate
/// challenges, for the app's own requests. `shared` serves the remembered
/// server; the address screen's probe makes one for the address typed (`target`,
/// matched by host so an http to https redirect keeps it), with access or without.
final class TrekAccessSession: NSObject, URLSessionTaskDelegate {
    static let shared = TrekAccessSession(target: nil, access: true)

    private let target: URL?
    private let access: Bool
    private(set) lazy var session: URLSession = URLSession(configuration: .default, delegate: self, delegateQueue: nil)

    init(target: URL?, access: Bool) {
        self.target = target
        self.access = access
    }

    private func inScope(_ url: URL?) -> Bool {
        guard access, let url else { return false }
        if let target { return TrekAccess.sameHost(url, target) }
        return TrekAccess.isServer(url)
    }

    private func inScope(_ space: URLProtectionSpace) -> Bool {
        guard access else { return false }
        if let host = target?.host?.lowercased() { return space.host.lowercased() == host }
        return TrekAccess.isServerSpace(space)
    }

    /// The request with the headers when it is in scope.
    func prepare(_ request: URLRequest) -> URLRequest {
        inScope(request.url) ? TrekAccess.adding(TrekAccess.headers, to: request) : request
    }

    func dataTask(with request: URLRequest, completion: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask {
        session.dataTask(with: prepare(request), completionHandler: completion)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        let answer = TrekAccess.clientCertificateAnswer(challenge) { [weak self] space in self?.inScope(space) ?? false }
        let (disposition, credential) = answer ?? (.performDefaultHandling, nil)
        completionHandler(disposition, credential)
    }

    /// A redirect keeps the headers only while it stays in scope.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard inScope(request.url) else {
            var stripped = request
            for header in TrekAccess.headers { stripped.setValue(nil, forHTTPHeaderField: header.name) }
            return completionHandler(stripped)
        }
        completionHandler(prepare(request))
    }
}

/// Stands in front of Capacitor's "bridge" message handler while sign-in
/// domains are set, and passes on only what the server's own pages (and the
/// bundled address screen) send. Capacitor's iOS bridge takes a message from
/// any page the WebView shows, and a proxy's login page now shows there.
final class TrekBridgeOriginGate: NSObject, WKScriptMessageHandler {
    private weak var inner: WKScriptMessageHandler?
    private let local: URL

    init(inner: WKScriptMessageHandler, local: URL) {
        self.inner = inner
        self.local = local
    }

    static func allows(_ origin: WKSecurityOrigin, server: URL?, local: URL) -> Bool {
        let scheme = origin.protocol.lowercased()
        let host = origin.host.lowercased()
        if scheme == local.scheme?.lowercased(), host == local.host?.lowercased() { return true }
        guard let server, scheme == server.scheme?.lowercased(), host == server.host?.lowercased() else { return false }
        // WebKit reports 0 for the scheme's default port.
        let port = origin.port == 0 ? (scheme == "http" ? 80 : 443) : origin.port
        return port == TrekAccess.port(server)
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard Self.allows(message.frameInfo.securityOrigin, server: TrekAccess.serverURL, local: local) else { return }
        inner?.userContentController(userContentController, didReceive: message)
    }
}
