package net.portswigger.mcp.evidence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RequestDiffTest {
    private val baseline =
        "POST /api/verify?next=/home HTTP/1.1\nHost: example.test\nAuthorization: Bearer aaa\nCookie: s=1; t=2\nContent-Type: application/json\nContent-Length: 27\n\n{\"role\":\"user\",\"a\":1}"

    @Test
    fun `identical requests produce no entries`() {
        val diff = RequestDiffer.diff(baseline, baseline)
        assertEquals(0, diff.totalChanges)
        assertTrue(diff.entries.isEmpty())
    }

    @Test
    fun `detects json body query cookie and header changes`() {
        val modified = baseline
            .replace("next=/home", "next=/admin")
            .replace("\"role\":\"user\"", "\"role\":\"admin\"")
            .replace("t=2", "t=3")
            .replace("Bearer aaa", "Bearer bbb")
        val diff = RequestDiffer.diff(baseline, modified)
        val locations = diff.entries.map { it.location }.toSet()
        assertTrue("query:next" in locations)
        assertTrue("body:\$.role" in locations)
        assertTrue("cookie:t" in locations)
        assertTrue("header:authorization" in locations)
        // Unchanged content is never reported.
        assertTrue(diff.entries.none { it.location == "body:\$.a" })
        assertTrue(diff.entries.none { it.location == "cookie:s" })
        val role = diff.entries.single { it.location == "body:\$.role" }
        assertEquals(DiffKind.CHANGED, role.kind)
        assertTrue(role.afterStart >= 0 && role.afterEnd > role.afterStart)
        assertEquals("admin", modified.substring(role.afterStart, role.afterEnd))
    }

    @Test
    fun `detects added and removed params`() {
        val modified = "POST /api/verify?next=/home&debug=true HTTP/1.1\nHost: example.test\n\n{}"
        val base = "POST /api/verify?next=/home&old=1 HTTP/1.1\nHost: example.test\n\n{}"
        val diff = RequestDiffer.diff(base, modified)
        assertTrue(diff.entries.any { it.kind == DiffKind.ADDED && it.location == "query:debug" })
        assertTrue(diff.entries.any { it.kind == DiffKind.REMOVED && it.location == "query:old" })
    }

    @Test
    fun `detects method and path changes`() {
        val diff = RequestDiffer.diff(
            "GET /a HTTP/1.1\nHost: x\n\n",
            "POST /b HTTP/1.1\nHost: x\n\n",
        )
        assertTrue(diff.entries.any { it.location == "request-line:method" })
        assertTrue(diff.entries.any { it.location == "request-line:path" })
    }

    @Test
    fun `differs form bodies per key`() {
        val diff = RequestDiffer.diff(
            "POST /f HTTP/1.1\nHost: x\nContent-Type: application/x-www-form-urlencoded\n\na=1&b=2",
            "POST /f HTTP/1.1\nHost: x\nContent-Type: application/x-www-form-urlencoded\n\na=1&b=9",
        )
        val entry = diff.entries.single { it.location == "body-form:b" }
        assertEquals("2", entry.before)
        assertEquals("9", entry.after)
    }
}
