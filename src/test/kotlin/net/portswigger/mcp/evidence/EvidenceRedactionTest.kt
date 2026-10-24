package net.portswigger.mcp.evidence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EvidenceRedactionTest {
    private val message =
        "POST /login?token=query-secret HTTP/1.1\nHost: example.test\n" +
            "Authorization: Bearer header-secret\nCookie: session=cookie-secret\n\n" +
            "{\"password\":\"body-secret\"}\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"

    @Test
    fun `secret spans cover values not names`() {
        val spans = EvidenceRedaction.secretSpans(message)
        assertTrue(spans.isNotEmpty())
        for (span in spans) {
            val text = message.substring(span.first, span.last + 1)
            assertTrue(
                text.contains("secret") || text.startsWith("eyJ"),
                "unexpected span: $text",
            )
        }
        // Header names and JSON keys stay visible.
        val covered = spans.flatMap { it.toList() }.toSet()
        fun isCovered(word: String): Boolean {
            val at = message.indexOf(word)
            return (at until at + word.length).any { it in covered }
        }
        assertTrue(!isCovered("Authorization"))
        assertTrue(!isCovered("\"password\""))
        assertTrue(isCovered("header-secret"))
        assertTrue(isCovered("body-secret"))
        assertTrue(isCovered("query-secret"))
        assertTrue(isCovered("cookie-secret"))
    }

    @Test
    fun `spans are merged and ordered`() {
        val spans = EvidenceRedaction.secretSpans(message)
        assertEquals(spans.sortedBy { it.first }, spans)
        for (window in spans.zipWithNext()) {
            assertTrue(window.first.last < window.second.first)
        }
    }

    @Test
    fun `clean messages yield no spans`() {
        assertTrue(EvidenceRedaction.secretSpans("GET / HTTP/1.1\nHost: x\n\n{}").isEmpty())
    }
}
