package net.portswigger.mcp.evidence

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.awt.Color
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PayloadEvidenceTest {
    private val baseReq = "POST /api/contact HTTP/1.1\nHost: x\n\n{\"url\":\"http://safe.test/r\",\"a\":1}"
    private val testReq = "POST /api/contact HTTP/1.1\nHost: x\n\n{\"url\":\"http://evil.test/poc\",\"a\":1}"

    @Test
    fun `hint inside json body is attributed to the body location`() {
        val base = "POST /m HTTP/1.1\nHost: x\nContent-Length: 20\n\n{\"url\":\"http://safe.test/r\"}"
        val test = "POST /m HTTP/1.1\nHost: x\nContent-Length: 21\n\n{\"url\":\"http://evil.test/poc\"}"
        val diff = RequestDiffer.diff(base, test)
        val payload = PayloadEvidence.detectPayload(test, diff, "http://evil.test/poc")
        assertEquals("body:\$.url", payload.location)
        assertEquals("http://evil.test/poc", test.substring(payload.startOffset, payload.endOffset))
    }

    @Test
    fun `heuristic payload is the largest changed value`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        assertEquals("http://evil.test/poc", payload.text)
        assertEquals(payload.text, testReq.substring(payload.startOffset, payload.endOffset))
        assertTrue(payload.heuristic)
    }

    @Test
    fun `hint locates url-encoded payloads in original form`() {
        val encoded = baseReq.replace(
            "\"url\":\"http://safe.test/r\"",
            "\"url\":\"http%3A%2F%2Fevil.test%2Fa%20b\"",
        )
        val diff = RequestDiffer.diff(baseReq, encoded)
        val payload = PayloadEvidence.detectPayload(encoded, diff, "http://evil.test/a b")
        assertEquals("http%3A%2F%2Fevil.test%2Fa%20b", payload.text)
        assertTrue(payload.fromHint)
        assertTrue("url" in payload.encodings)
    }

    @Test
    fun `missing hint is an explicit error`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        assertFailsWith<IllegalArgumentException> {
            PayloadEvidence.detectPayload(testReq, diff, "no-such-payload-anywhere")
        }
    }

    @Test
    fun `no modifications means no payload`() {
        val diff = RequestDiffer.diff(baseReq, baseReq)
        assertFailsWith<IllegalArgumentException> {
            PayloadEvidence.detectPayload(baseReq, diff, null)
        }
    }

    @Test
    fun `reflection in response is success with high confidence`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = "HTTP/1.1 200 OK\n\n{\"fetched\":\"http://evil.test/poc content\"}",
            baselineResponse = "HTTP/1.1 200 OK\n\n{\"fetched\":\"nothing\"}",
            payload = payload, objective = "server fetches the supplied url",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.SUCCESS, analysis.verdict)
        assertEquals("high", analysis.confidence)
        assertTrue(analysis.evidence.any { it.kind == EvidenceKind.PAYLOAD_REFLECTION })
        for (fragment in analysis.evidence) {
            assertEquals(
                fragment.text,
                "HTTP/1.1 200 OK\n\n{\"fetched\":\"http://evil.test/poc content\"}"
                    .substring(fragment.startOffset, fragment.endOffset),
            )
        }
    }

    @Test
    fun `novel objective fragment without reflection is still success medium`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = "HTTP/1.1 200 OK\n\nfetched remote content ok",
            baselineResponse = "HTTP/1.1 200 OK\n\nnothing here",
            payload = payload, objective = "response contains fetched remote content",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.SUCCESS, analysis.verdict)
        assertEquals("medium", analysis.confidence)
    }

    @Test
    fun `identical responses are inconclusive not failed`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val body = "HTTP/1.1 200 OK\n\nsame"
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = body, baselineResponse = body,
            payload = payload, objective = "unrelated objective words xyz",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.INCONCLUSIVE, analysis.verdict)
    }

    @Test
    fun `volatile headers never become evidence`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = "HTTP/1.1 200 OK\nDate: TODAY\nContent-Length: 99\n\nsame body",
            baselineResponse = "HTTP/1.1 200 OK\nDate: YESTERDAY\nContent-Length: 98\n\nsame body",
            payload = payload, objective = "unrelated objective words xyz",
            evidenceHint = null, testRequest = testReq,
        )
        assertTrue(analysis.evidence.none { it.text.contains("TODAY") || it.text.contains("99") })
        assertTrue(analysis.volatileExcluded >= 2)
    }

    @Test
    fun `unlinked delta is observed`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = "HTTP/1.1 200 OK\n\nbrand new line",
            baselineResponse = "HTTP/1.1 200 OK\n\nold",
            payload = payload, objective = "unrelated objective words xyz",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.OBSERVED, analysis.verdict)
    }

    @Test
    fun `rejection status shift without reflection is failed`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = "HTTP/1.1 403 Forbidden\n\nblocked",
            baselineResponse = "HTTP/1.1 200 OK\n\nok",
            payload = payload, objective = "unrelated objective words xyz",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.FAILED, analysis.verdict)
    }

    @Test
    fun `missing test response is inconclusive`() {
        val diff = RequestDiffer.diff(baseReq, testReq)
        val payload = PayloadEvidence.detectPayload(testReq, diff, null)
        val analysis = PayloadEvidence.analyzeResponse(
            testResponse = null, baselineResponse = null,
            payload = payload, objective = "anything",
            evidenceHint = null, testRequest = testReq,
        )
        assertEquals(ExploitVerdict.INCONCLUSIVE, analysis.verdict)
        assertTrue(analysis.evidence.isEmpty())
    }
}

class EvidenceOverlayTest {
    private fun samplePng(width: Int = 400, height: Int = 200): ByteArray {
        val image = BufferedImage(width, height, BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        graphics.color = java.awt.Color.WHITE
        graphics.fillRect(0, 0, width, height)
        graphics.dispose()
        val output = ByteArrayOutputStream()
        ImageIO.write(image, "png", output)
        return output.toByteArray()
    }

    @Test
    fun `derivative preserves original pixels and adds labeled strip`() {
        val original = samplePng()
        val derivative = EvidenceOverlay.annotate(
            original,
            listOf("verdict: success (confidence high)", "payload @body:\$.url offsets 10-20"),
        )
        val decoded = ImageIO.read(ByteArrayInputStream(derivative))
        assertNotNull(decoded)
        assertEquals(400, decoded.width)
        assertTrue(decoded.height > 200)
        // Top region is the untouched original (all white).
        assertEquals(java.awt.Color.WHITE.rgb, decoded.getRGB(5, 5))
        // Caption strip is dark.
        assertTrue(decoded.getRGB(5, decoded.height - 5) != java.awt.Color.WHITE.rgb)
    }

    @Test
    fun `invalid bytes are an explicit error`() {
        assertFailsWith<IllegalArgumentException> {
            EvidenceOverlay.annotate("not-a-png".toByteArray(), listOf("x"))
        }
    }

    @Test
    fun `numbering is deterministic across sides`() {
        val numbered = BoundingBox.numberBoxes(
            listOf(
                PlacedBox(BoxSide.RESPONSE, 10, 50, 20, 10, "b"),
                PlacedBox(BoxSide.REQUEST, 10, 90, 20, 10, "a"),
                PlacedBox(BoxSide.REQUEST, 10, 10, 20, 10, "c"),
            )
        )
        assertEquals(listOf(1, 2, 3), numbered.map { it.number })
        assertEquals("c", numbered[0].box.label)
        assertEquals("a", numbered[1].box.label)
        assertEquals("b", numbered[2].box.label)
    }

    @Test
    fun `numbered derivative draws badges and legend`() {
        val annotated = EvidenceOverlay.annotateNumbered(
            samplePng(),
            BoundingBox.numberBoxes(
                listOf(PlacedBox(BoxSide.REQUEST, 50, 60, 80, 20, "payload", "payload @body offsets 1-2"))
            ),
            listOf("verdict: success"),
            listOf("payload @body offsets 1-2"),
        )
        val decoded = ImageIO.read(ByteArrayInputStream(annotated))
        assertNotNull(decoded)
        assertEquals(400, decoded.width)
        // Caption (1 title + 1 caption + 1 legend) grows the image.
        assertTrue(decoded.height > 200)
        // Badge anchored at box top-right corner (50+80+5, 60-5) clamped inside.
        // Center holds the white digit; sample inside the red ring instead.
        assertEquals(java.awt.Color(255, 0, 0).rgb, decoded.getRGB(127, 48))
        // Box edges still red (left edge x=45, bottom edge y=85).
        assertEquals(java.awt.Color(255, 0, 0).rgb, decoded.getRGB(45, 70))
        // Label pill: dark strip left of the badge ("payload" pill spans
        // ~x61-123); sample its padding clear of glyphs and box edges.
        assertEquals(java.awt.Color(24, 24, 28).rgb, decoded.getRGB(63, 47))
    }

    @Test
    fun `redaction fill covers text solid black`() {
        val image = java.awt.image.BufferedImage(200, 100, java.awt.image.BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        graphics.color = Color.WHITE
        graphics.fillRect(0, 0, 200, 100)
        graphics.color = Color.BLACK
        graphics.drawString("secret", 60, 40)
        graphics.dispose()
        val output = java.io.ByteArrayOutputStream()
        ImageIO.write(image, "png", output)
        val redacted = BoundingBox.drawRedactions(
            output.toByteArray(), listOf(PlacedBox(BoxSide.REQUEST, 50, 30, 60, 20, BoundingBox.REDACTED_LABEL))
        )
        val decoded = ImageIO.read(ByteArrayInputStream(redacted))
        assertNotNull(decoded)
        assertEquals(200, decoded.width)
        assertEquals(Color.BLACK.rgb, decoded.getRGB(60, 40))
        // Outside the fill stays untouched.
        assertEquals(Color.WHITE.rgb, decoded.getRGB(10, 10))
    }
}
