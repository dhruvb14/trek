package com.liketrek.trek.access

import com.liketrek.trek.access.TrekAccess.Header
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The rules behind the access headers and their scope (access/TrekAccess.kt). */
class TrekAccessTest {
    @Test
    fun headersFollowTheSameLimitsAsTheAddressScreen() {
        assertTrue(TrekAccess.isValid(Header("CF-Access-Client-Id", "abc.access")))
        assertTrue(TrekAccess.isValid(Header("X-A", "tab\tinside")))
        assertFalse(TrekAccess.isValid(Header("Bad Name", "x")))
        assertFalse(TrekAccess.isValid(Header("X-A", "")))
        assertFalse(TrekAccess.isValid(Header("X-A", "a\r\nX-Evil: 1")))
        assertFalse(TrekAccess.isValid(Header("X-A", "x".repeat(TrekAccess.MAX_VALUE + 1))))
        assertFalse(TrekAccess.isValid(Header("Ünïcode", "x")))
        assertFalse(TrekAccess.isValid(listOf(Header("X-A", "1"), Header("x-a", "2"))))
        assertFalse(TrekAccess.isValid((0..TrekAccess.MAX_HEADERS).map { Header("X-H$it", "v") }))
        assertTrue(TrekAccess.isValid(emptyList()))
    }

    @Test
    fun scopeIsTheServersOriginForTheWebViewAndItsHostForTheProbe() {
        assertTrue(TrekAccess.sameOrigin("https://trek.example.com/api/x", "https://TREK.example.com/"))
        assertTrue(TrekAccess.sameOrigin("https://trek.example.com:443/a", "https://trek.example.com"))
        assertFalse(TrekAccess.sameOrigin("http://trek.example.com/a", "https://trek.example.com"))
        assertFalse(TrekAccess.sameOrigin("https://trek.example.com:8443/a", "https://trek.example.com"))
        assertFalse(TrekAccess.sameOrigin("https://trek.example.com.evil.test/a", "https://trek.example.com"))
        assertTrue(TrekAccess.sameHost("https://trek.example.com/a", "http://trek.example.com:3001"))
        assertFalse(TrekAccess.sameHost("https://tiles.example.com/a", "https://trek.example.com"))
    }

    @Test
    fun originIsSpelledAsLocationOriginSpellsIt() {
        assertEquals("https://trek.example.com", TrekAccess.origin("https://Trek.Example.com/trek/"))
        assertEquals("http://192.168.1.10:3001", TrekAccess.origin("http://192.168.1.10:3001/"))
        assertEquals("http://nas.local", TrekAccess.origin("http://nas.local:80"))
        assertNull(TrekAccess.origin("not a url"))
    }

    @Test
    fun theAppsConnectionKeepsTheRequestsHeadersAndAddsWhatIsMissing() {
        val access = listOf(Header("CF-Access-Client-Id", "id"), Header("CF-Access-Client-Secret", "secret"))
        val request = mapOf("Accept" to "text/html", "cf-access-client-id" to "page", "Accept-Encoding" to "br", "Cookie" to "a=b")
        assertEquals(
            mapOf("Accept" to "text/html", "cf-access-client-id" to "page", "CF-Access-Client-Secret" to "secret"),
            TrekAccess.outgoingHeaders(request, access)
        )
        assertFalse(TrekAccess.carriesAll(request, access))
        assertTrue(TrekAccess.carriesAll(request + ("cf-access-client-secret" to "s"), access))
        assertTrue(TrekAccess.carriesAll(null, emptyList()))
    }

    @Test
    fun storedHeadersLeaveOutWhatIsNotValid() {
        val json = TrekAccess.headersToJson(listOf(Header("X-A", "1"))).toString()
        assertEquals(listOf(Header("X-A", "1")), TrekAccess.headersFromJson(json))
        assertEquals(listOf(Header("X-B", "2")), TrekAccess.headersFromJson("""[{"name":"Bad Name","value":"1"},{"name":"X-B","value":"2"}]"""))
        assertEquals(emptyList<Header>(), TrekAccess.headersFromJson("not json"))
    }

    @Test
    fun signInDomainsAreHostsOrWildcardsOverADomain() {
        assertTrue(TrekAccess.isValidLoginHost("myteam.cloudflareaccess.com"))
        assertTrue(TrekAccess.isValidLoginHost("*.example.com"))
        assertTrue(TrekAccess.isValidLoginHost("pangolin"))
        assertFalse(TrekAccess.isValidLoginHost("*.com"))
        assertFalse(TrekAccess.isValidLoginHost("-bad.example.com"))
        assertFalse(TrekAccess.isValidLoginHost("ex_ample.com"))
        assertFalse(TrekAccess.isValidLoginHost("Upper.example.com"))
        assertFalse(TrekAccess.isValidLoginHost(""))
    }

    @Test
    fun aSignInDomainMatchesItselfAndTheSubdomainsOfAWildcard() {
        val entries = listOf("myteam.cloudflareaccess.com", "*.example.com")
        assertTrue(TrekAccess.matchesLoginHost("MyTeam.cloudflareaccess.com", entries))
        assertTrue(TrekAccess.matchesLoginHost("auth.example.com", entries))
        assertTrue(TrekAccess.matchesLoginHost("a.b.example.com", entries))
        assertFalse(TrekAccess.matchesLoginHost("example.com", entries))
        assertFalse(TrekAccess.matchesLoginHost("evilexample.com", entries))
        assertFalse(TrekAccess.matchesLoginHost("other.cloudflareaccess.com", entries))
    }
}
