package net.portswigger.mcp.evidence

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SmartEvidenceTest {
    @Test
    fun `goal with quoted field proposes keyword and jsonpath`() {
        val proposed = GoalCriteria.propose(
            goal = """Find the "access_token" field in the response.""",
            requestText = "GET / HTTP/1.1",
            responseText = "{}",
        )
        val expressions = proposed.criteria.map { it.type to it.expression }.toSet()
        assertTrue(expressions.contains(CriterionType.KEYWORD to "access_token"))
        assertTrue(expressions.contains(CriterionType.JSONPATH to "\$..access_token"))
    }

    @Test
    fun `goal with external url proposes host token`() {
        val proposed = GoalCriteria.propose(
            goal = "The request supplies an external URL. Find the response field " +
                "containing content retrieved from that URL.",
            requestText = "POST http://evil.example/hook HTTP/1.1\nHost: evil.example",
            responseText = "fetched from evil.example ok",
        )
        assertTrue(proposed.criteria.any { it.expression == "evil.example" })
    }

    @Test
    fun `goal end to end verifies candidates against original text`() {
        val response = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nfetched http://evil.example/hook body here"
        val proposed = GoalCriteria.propose(
            goal = "The request supplies external URL http://evil.example/hook. " +
                "Find the response field containing content retrieved from that URL.",
            requestText = "POST /x HTTP/1.1",
            responseText = response,
        )
        val outcome = EvidenceLocator.locateInMessage(response, proposed.criteria)
        assertTrue(outcome.matches.isNotEmpty())
        for (match in outcome.matches) {
            assertEquals(match.matchedText, response.substring(match.startOffset, match.endOffset))
        }
    }

    @Test
    fun `goal with nothing concrete is explicit`() {
        val proposed = GoalCriteria.propose(
            goal = "show me the thing",
            requestText = "GET / HTTP/1.1",
            responseText = "nothing relevant",
        )
        assertTrue(proposed.criteria.isEmpty() || proposed.notes.isNotEmpty())
    }

    @Test
    fun `parseCriteria rejects unknown types and empty expressions`() {
        assertFailsWith<IllegalArgumentException> {
            SmartEvidence.parseCriteria(
                BurpSmartEvidence(request_id = "0", select = listOf(SelectCriterion("xpath", "//a")))
            )
        }
        assertFailsWith<IllegalArgumentException> {
            SmartEvidence.parseCriteria(
                BurpSmartEvidence(request_id = "0", select = listOf(SelectCriterion("keyword", "")))
            )
        }
    }

    @Test
    fun `validate requires select or goal and sane bounds`() {
        assertFailsWith<IllegalArgumentException> { SmartEvidence.validate(BurpSmartEvidence(request_id = "0")) }
        assertFailsWith<IllegalArgumentException> {
            SmartEvidence.validate(BurpSmartEvidence(request_id = "0", goal = "x", context_lines = 99))
        }
        assertFailsWith<IllegalArgumentException> {
            SmartEvidence.validate(BurpSmartEvidence(request_id = "0", goal = "x", max_regions = 0))
        }
        SmartEvidence.validate(BurpSmartEvidence(request_id = "id:7", goal = "find it"))
    }

    @Test
    fun `region box targets convert verified matches`() {
        val region = EvidenceRegion(
            side = EvidenceSide.RESPONSE,
            startLine = 1, endLine = 3, startOffset = 0, endOffset = 60,
            matches = listOf(
                LocatedMatch(0, CriterionType.KEYWORD, "needle", 10, 16, "needle", 2),
                LocatedMatch(0, CriterionType.KEYWORD, "needle", 40, 46, "needle", 3),
            ),
        )
        val targets = SmartEvidence.regionBoxTargets(region)
        assertEquals(2, targets.size)
        assertTrue(targets.all { it.side == BoxSide.RESPONSE && it.label == BoundingBox.HIGHLIGHT_LABEL })
        assertEquals(10, targets[0].approxOffset)
        assertEquals("needle", targets[0].text)
    }

    @Test
    fun `region box targets skip oversized fragments`() {
        val region = EvidenceRegion(
            side = EvidenceSide.REQUEST,
            startLine = 1, endLine = 1, startOffset = 0, endOffset = 600,
            matches = listOf(
                LocatedMatch(0, CriterionType.REGEX, "x+", 0, 501, "y".repeat(501), 1),
            ),
        )
        assertTrue(SmartEvidence.regionBoxTargets(region).isEmpty())
    }
}
