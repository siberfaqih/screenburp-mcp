package net.portswigger.mcp.evidence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class EvidenceLocatorTest {
    private val message = "POST /verify HTTP/1.1\nHost: example.test\n\n{\"token\":\"abc\",\"role\":\"admin\"}"

    @Test
    fun `keyword matches are exact verified offsets`() {
        val outcome = EvidenceLocator.locateInMessage(
            message, listOf(MatchCriterion(0, CriterionType.KEYWORD, "admin"))
        )
        assertEquals(1, outcome.matches.size)
        val match = outcome.matches.single()
        assertEquals("admin", message.substring(match.startOffset, match.endOffset))
        assertEquals(match.matchedText, message.substring(match.startOffset, match.endOffset))
        assertEquals(4, match.lineNumber)
    }

    @Test
    fun `keyword search is case-insensitive by default`() {
        val outcome = EvidenceLocator.locateInMessage(
            message, listOf(MatchCriterion(0, CriterionType.KEYWORD, "HOST"))
        )
        assertEquals(1, outcome.matches.size)
        assertEquals("Host", outcome.matches.single().matchedText)
    }

    @Test
    fun `regex matches honor case sensitivity flag`() {
        val sensitive = EvidenceLocator.locateInMessage(
            message, listOf(MatchCriterion(0, CriterionType.REGEX, "host", caseSensitive = true))
        )
        assertTrue(sensitive.matches.isEmpty())
        val insensitive = EvidenceLocator.locateInMessage(
            message, listOf(MatchCriterion(0, CriterionType.REGEX, "host"))
        )
        assertEquals(1, insensitive.matches.size)
    }

    @Test
    fun `invalid regex is an explicit error`() {
        assertFailsWith<IllegalArgumentException> {
            EvidenceLocator.locateInMessage(message, listOf(MatchCriterion(0, CriterionType.REGEX, "([a-z")))
        }
    }

    @Test
    fun `jsonpath locates values with node paths`() {
        val outcome = EvidenceLocator.locateInMessage(
            message, listOf(MatchCriterion(0, CriterionType.JSONPATH, "$..role"))
        )
        assertEquals(1, outcome.matches.size)
        val match = outcome.matches.single()
        assertEquals("admin", match.matchedText)
        assertEquals("$.role", match.nodePath)
    }

    @Test
    fun `jsonpath on non-json body is skipped explicitly`() {
        val outcome = EvidenceLocator.locateInMessage(
            "GET / HTTP/1.1\nHost: x\n\nnot json",
            listOf(MatchCriterion(0, CriterionType.JSONPATH, "$..a"))
        )
        assertTrue(outcome.matches.isEmpty())
        assertEquals(1, outcome.skipped.size)
        assertTrue(outcome.skipped.single().contains("$..a"))
    }

    @Test
    fun `context lines expand regions and distant matches split`() {
        val lines = (1..100).joinToString("\n") { if (it == 10 || it == 90) "MARK" else "filler $it" }
        val outcome = EvidenceLocator.locateInMessage(
            lines, listOf(MatchCriterion(0, CriterionType.KEYWORD, "MARK"))
        )
        assertEquals(2, outcome.matches.size)
        val split = EvidenceLocator.groupIntoRegions(
            EvidenceSide.RESPONSE, lines, outcome.matches, contextLines = 2, mergeGapLines = 5
        )
        assertEquals(2, split.size)
        assertEquals(8, split[0].startLine)
        assertEquals(12, split[0].endLine)
        assertEquals(88, split[1].startLine)
        assertEquals(92, split[1].endLine)
        val merged = EvidenceLocator.groupIntoRegions(
            EvidenceSide.RESPONSE, lines, outcome.matches, contextLines = 2, mergeGapLines = 200
        )
        assertEquals(1, merged.size)
        assertEquals(2, merged.single().matches.size)
    }

    @Test
    fun `match caps are reported explicitly`() {
        val lines = (1..60).joinToString("\n") { "hit $it" }
        val outcome = EvidenceLocator.locateInMessage(
            lines, listOf(MatchCriterion(0, CriterionType.KEYWORD, "hit"))
        )
        assertEquals(EvidenceLocator.MAX_MATCHES_PER_CRITERION, outcome.matches.size)
        assertEquals(listOf(0), outcome.cappedCriteria)
    }
}
