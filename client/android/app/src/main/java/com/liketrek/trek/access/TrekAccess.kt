package com.liketrek.trek.access

import android.content.Context
import android.security.KeyChain
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.webkit.ClientCertRequest
import android.webkit.CookieManager
import android.webkit.ServiceWorkerClient
import android.webkit.ServiceWorkerController
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URI
import java.net.URL
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509ExtendedKeyManager
import org.json.JSONArray
import org.json.JSONObject

/**
 * Access to a TREK server behind a zero-trust or identity-aware proxy
 * (Cloudflare Access, Pomerium, oauth2-proxy, an mTLS front end): the custom
 * headers the user set on the address screen (client/native-shell/access.ts)
 * and the client certificate picked from the system's KeyChain.
 *
 * Both go to the remembered server only, never to map tiles, link previews or
 * another host. Where each request path picks them up:
 * - the WebView's GETs to the server (pages, scripts, images, the service
 *   worker's): [intercept], which sends them again through the app with the
 *   headers and the WebView's cookies;
 * - the UI's other fetch and XMLHttpRequest calls: [installScript]
 *   (client/native-shell/static/access-headers.js);
 * - the WebView's certificate requests: [answer];
 * - the address screen's probe: [probe].
 *
 * The WebSocket gets neither header nor interception: it depends on the
 * session cookie the proxy sets on the first authenticated load.
 */
object TrekAccess {
    data class Header(val name: String, val value: String)

    data class CertificateInfo(val subject: String, val expires: String?)

    data class ProbeAnswer(val status: Int, val body: String, val url: String)

    /** The same limits as client/src/native/accessHeaders.ts, held again here. */
    const val MAX_HEADERS = 16
    const val MAX_VALUE = 8192
    private const val TOKEN = "!#$%&'*+.^_`|~-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

    private const val PREFS = "trek_access"
    private const val KEY_HEADERS = "headers"
    private const val KEY_ALIAS = "certificate_alias"
    private const val KEYSTORE_ALIAS = "trek-access-headers"
    private const val TIMEOUT_MS = 30_000
    private const val MAX_REDIRECTS = 5

    /** Response headers the app has already dealt with (gzip undone, cookies stored) or that describe the hop. */
    private val DROPPED = setOf("content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "set-cookie")
    private val HOP_BY_HOP = setOf("connection", "keep-alive", "transfer-encoding", "te", "upgrade", "host", "content-length", "accept-encoding", "cookie")

    /** The remembered server, set while the WebView shows it (MainActivity). */
    @Volatile
    var server: String? = null

    @Volatile
    private var cachedHeaders: List<Header>? = null

    @Volatile
    private var socketFactory: Pair<String, SSLSocketFactory>? = null

    // ---- Rules (no Android types, so the JVM tests reach them) ----

    fun isValid(header: Header): Boolean {
        if (header.name.isEmpty() || header.name.any { it !in TOKEN }) return false
        if (header.value.isEmpty() || header.value.length > MAX_VALUE) return false
        return header.value.none { (it < ' ' && it != '\t') || it == '\u007f' }
    }

    fun isValid(headers: List<Header>): Boolean =
        headers.size <= MAX_HEADERS && headers.all(::isValid) &&
            headers.map { it.name.lowercase(Locale.ROOT) }.toSet().size == headers.size

    fun port(uri: URI): Int = if (uri.port != -1) uri.port else if (uri.scheme.equals("http", true)) 80 else 443

    /** Same scheme, host and port: the browser's idea of one origin. */
    fun sameOrigin(a: String, b: String): Boolean {
        val x = runCatching { URI(a) }.getOrNull() ?: return false
        val y = runCatching { URI(b) }.getOrNull() ?: return false
        return x.scheme.equals(y.scheme, true) && x.host != null && x.host.equals(y.host, true) && port(x) == port(y)
    }

    fun sameHost(a: String, b: String): Boolean {
        val x = runCatching { URI(a).host }.getOrNull() ?: return false
        val y = runCatching { URI(b).host }.getOrNull() ?: return false
        return x.equals(y, true)
    }

    /** The origin as `location.origin` spells it, without a default port. */
    fun origin(url: String): String? {
        val uri = runCatching { URI(url) }.getOrNull() ?: return null
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
        val host = uri.host?.lowercase(Locale.ROOT) ?: return null
        val defaultPort = if (scheme == "http") 80 else 443
        return if (port(uri) == defaultPort) "$scheme://$host" else "$scheme://$host:${port(uri)}"
    }

    /** Whether a request already carries every access header (the page script set them). */
    fun carriesAll(requestHeaders: Map<String, String>?, headers: List<Header>): Boolean {
        val present = requestHeaders.orEmpty().keys.map { it.lowercase(Locale.ROOT) }.toSet()
        return headers.all { it.name.lowercase(Locale.ROOT) in present }
    }

    /** The request's own headers for a connection the app makes, and the access headers it lacks. */
    fun outgoingHeaders(requestHeaders: Map<String, String>?, headers: List<Header>): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        requestHeaders.orEmpty().forEach { (name, value) -> if (name.lowercase(Locale.ROOT) !in HOP_BY_HOP) out[name] = value }
        val present = out.keys.map { it.lowercase(Locale.ROOT) }.toSet()
        headers.forEach { if (it.name.lowercase(Locale.ROOT) !in present) out[it.name] = it.value }
        return out
    }

    fun headersToJson(headers: List<Header>): JSONArray =
        JSONArray().apply { headers.forEach { put(JSONObject().put("name", it.name).put("value", it.value)) } }

    fun headersFromJson(json: String): List<Header> = runCatching {
        val array = JSONArray(json)
        (0 until array.length()).mapNotNull { i ->
            val item = array.optJSONObject(i) ?: return@mapNotNull null
            Header(item.optString("name"), item.optString("value")).takeIf(::isValid)
        }
    }.getOrDefault(emptyList())

    // ---- Storage ----

    private fun prefs(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun headers(context: Context): List<Header> {
        cachedHeaders?.let { return it }
        val stored = prefs(context).getString(KEY_HEADERS, null)
        val loaded = stored?.let { decrypt(it) }?.let { headersFromJson(String(it, Charsets.UTF_8)) } ?: emptyList()
        cachedHeaders = loaded
        return loaded
    }

    /** Replaces the headers; false when one breaks the limits or the key store refused. */
    fun setHeaders(context: Context, headers: List<Header>): Boolean {
        if (!isValid(headers)) return false
        val editor = prefs(context).edit()
        if (headers.isEmpty()) {
            editor.remove(KEY_HEADERS)
        } else {
            val sealed = runCatching { encrypt(headersToJson(headers).toString().toByteArray(Charsets.UTF_8)) }.getOrNull() ?: return false
            editor.putString(KEY_HEADERS, sealed)
        }
        if (!editor.commit()) return false
        cachedHeaders = headers
        return true
    }

    /**
     * The headers are sealed with an AES key that never leaves the
     * AndroidKeyStore. A backup could not open them anywhere else (the app
     * allows none), and a key store that lost its key reads as no headers.
     */
    private fun secretKey(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEYSTORE_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private fun encrypt(plain: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val iv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP)
        return iv + ":" + Base64.encodeToString(cipher.doFinal(plain), Base64.NO_WRAP)
    }

    private fun decrypt(sealed: String): ByteArray? = runCatching {
        val parts = sealed.split(":")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, Base64.decode(parts[0], Base64.NO_WRAP)))
        cipher.doFinal(Base64.decode(parts[1], Base64.NO_WRAP))
    }.getOrNull()

    /** The KeyChain alias the user picked; the key itself stays in the system's store. */
    fun alias(context: Context): String? = prefs(context).getString(KEY_ALIAS, null)

    fun setAlias(context: Context, alias: String?) {
        val editor = prefs(context).edit()
        if (alias == null) editor.remove(KEY_ALIAS) else editor.putString(KEY_ALIAS, alias)
        editor.commit()
        socketFactory = null
    }

    /** The certificate behind an alias, or null when the app may not read it (any more). Not on the main thread. */
    fun describe(context: Context, alias: String): CertificateInfo? {
        val certificate = runCatching { KeyChain.getCertificateChain(context, alias)?.firstOrNull() }.getOrNull() ?: return null
        val name = certificate.subjectX500Principal.name
        val subject = Regex("(?:^|,)CN=([^,]+)").find(name)?.groupValues?.get(1) ?: name
        val format = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }
        return CertificateInfo(subject, format.format(certificate.notAfter))
    }

    // ---- Connections the app makes ----

    /** Offers the picked certificate to whichever server the connection is made to: only ever one in scope. */
    private class AliasKeyManager(private val context: Context, private val alias: String) : X509ExtendedKeyManager() {
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String = alias

        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String = alias

        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf(alias)

        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null

        override fun getCertificateChain(name: String?): Array<X509Certificate>? =
            runCatching { KeyChain.getCertificateChain(context, alias) }.getOrNull()

        override fun getPrivateKey(name: String?): PrivateKey? = runCatching { KeyChain.getPrivateKey(context, alias) }.getOrNull()
    }

    private fun socketFactory(context: Context, alias: String): SSLSocketFactory {
        socketFactory?.let { (cached, factory) -> if (cached == alias) return factory }
        val ssl = SSLContext.getInstance("TLS")
        // The system's trust store as it is: a private CA is trusted through Android's settings.
        ssl.init(arrayOf(AliasKeyManager(context.applicationContext, alias)), null, null)
        return ssl.socketFactory.also { socketFactory = alias to it }
    }

    /** A connection with the access headers and certificate when `inScope`, and neither otherwise. */
    private fun open(context: Context, url: URL, inScope: Boolean, requestHeaders: Map<String, String>?): HttpURLConnection {
        val connection = url.openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = false
        connection.connectTimeout = TIMEOUT_MS
        connection.readTimeout = TIMEOUT_MS
        val access = if (inScope) headers(context) else emptyList()
        outgoingHeaders(requestHeaders, access).forEach { (name, value) -> connection.setRequestProperty(name, value) }
        val alias = if (inScope) alias(context) else null
        if (alias != null && connection is HttpsURLConnection) connection.sslSocketFactory = socketFactory(context, alias)
        return connection
    }

    /**
     * The WebView's GET to the server, sent again through the app with the
     * access headers, the WebView's cookies and the certificate; null hands it
     * back to the WebView. So does a redirect: a WebResourceResponse cannot
     * carry one, and following it here would show a proxy's login page under
     * the server's origin.
     */
    fun intercept(context: Context, request: WebResourceRequest): WebResourceResponse? {
        val target = server ?: return null
        val url = request.url.toString()
        if (!request.method.equals("GET", true) || !sameOrigin(url, target)) return null
        val access = headers(context)
        if (access.isEmpty() || carriesAll(request.requestHeaders, access)) return null
        return try {
            val connection = open(context, URL(url), true, request.requestHeaders)
            val cookies = CookieManager.getInstance()
            cookies.getCookie(url)?.let { connection.setRequestProperty("Cookie", it) }
            val status = connection.responseCode
            connection.headerFields.entries
                .filter { it.key.equals("Set-Cookie", true) }
                .flatMap { it.value }
                .forEach { cookies.setCookie(url, it) }
            if (status < 200 || status in 300..399 || status > 599) {
                connection.disconnect()
                return null
            }
            val type = connection.contentType ?: "application/octet-stream"
            val charset = Regex("charset=([^;]+)", RegexOption.IGNORE_CASE).find(type)?.groupValues?.get(1)?.trim()
            val body = (if (status >= 400) connection.errorStream else connection.inputStream) ?: ByteArrayInputStream(ByteArray(0))
            val headers = HashMap<String, String>()
            connection.headerFields.forEach { (name, values) ->
                if (name != null && name.lowercase(Locale.ROOT) !in DROPPED) headers[name] = values.joinToString(", ")
            }
            val reason = connection.responseMessage?.takeIf { it.isNotBlank() } ?: "OK"
            WebResourceResponse(type.substringBefore(';').trim(), charset, status, reason, headers, body)
        } catch (error: Exception) {
            // Unreachable, or an answer a WebResourceResponse cannot carry: the WebView tries itself.
            null
        }
    }

    /**
     * The service worker's requests (Workbox precaching and its network-first
     * routes) do not pass the WebView's client, so they get the same treatment
     * here, in front of what Capacitor answers them with.
     */
    fun interceptServiceWorker(context: Context, fallback: (WebResourceRequest) -> WebResourceResponse?) {
        if (headers(context).isEmpty()) return
        val app = context.applicationContext
        ServiceWorkerController.getInstance().setServiceWorkerClient(object : ServiceWorkerClient() {
            override fun shouldInterceptRequest(request: WebResourceRequest): WebResourceResponse? =
                intercept(app, request) ?: fallback(request)
        })
    }

    /** The document-start script that adds the headers to the UI's other fetch and XMLHttpRequest calls. */
    fun installScript(context: Context, webView: WebView) {
        val target = server ?: return
        val access = headers(context)
        val origin = origin(target) ?: return
        if (access.isEmpty() || !WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) return
        val source = runCatching {
            context.assets.open("public/access-headers.js").use { it.readBytes().toString(Charsets.UTF_8) }
        }.getOrNull() ?: return
        val config = JSONObject().put("origin", origin).put("headers", headersToJson(access))
        val script = source.replace("TREK_ACCESS_CONFIG", config.toString())
        runCatching { WebViewCompat.addDocumentStartJavaScript(webView, script, setOf(origin)) }
    }

    /**
     * The WebView asks for a client certificate: the picked one for the
     * server's host, nothing for any other (false leaves it to the default,
     * which declines). KeyChain is read off the main thread.
     */
    fun answer(context: Context, request: ClientCertRequest): Boolean {
        val target = server?.let { runCatching { URI(it) }.getOrNull() } ?: return false
        val alias = alias(context) ?: return false
        if (!request.host.equals(target.host, true) || request.port != port(target)) return false
        val app = context.applicationContext
        Thread {
            val key = runCatching { KeyChain.getPrivateKey(app, alias) }.getOrNull()
            val chain = runCatching { KeyChain.getCertificateChain(app, alias) }.getOrNull()
            if (key != null && chain != null) request.proceed(key, chain) else request.ignore()
        }.start()
        return true
    }

    /**
     * The address screen's check of a server. With `access`, the headers and
     * certificate go to the typed address's host and its redirects on that host
     * (http to https keeps them); a redirect elsewhere goes without.
     */
    @Throws(IOException::class)
    fun probe(context: Context, address: String, timeoutMs: Int, access: Boolean): ProbeAnswer {
        var current = URL(address)
        repeat(MAX_REDIRECTS + 1) {
            val inScope = access && sameHost(current.toString(), address)
            val connection = open(context, current, inScope, mapOf("Accept" to "application/json"))
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            val status = connection.responseCode
            if (status in 300..399) {
                val location = connection.getHeaderField("Location")
                connection.disconnect()
                if (location == null) return ProbeAnswer(status, "", current.toString())
                current = URL(current, location)
                return@repeat
            }
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            val body = stream?.use { it.readBytes().toString(Charsets.UTF_8) } ?: ""
            return ProbeAnswer(status, body, current.toString())
        }
        throw IOException("Too many redirects")
    }
}
