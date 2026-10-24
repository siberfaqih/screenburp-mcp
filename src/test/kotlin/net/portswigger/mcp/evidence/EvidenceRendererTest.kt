package net.portswigger.mcp.evidence

import java.io.ByteArrayInputStream
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class EvidenceRendererTest {
    @Test
    fun `renders a valid PNG without a display`() {
        System.setProperty("java.awt.headless", "true")
        val image = EvidenceRenderer.render(
            request = "GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n",
            response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello",
            title = "Evidence",
            redactSecrets = true,
            maxBodyCharacters = 4_000,
        )

        assertTrue(image.png.take(8).toByteArray().contentEquals(byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)))
        val decoded = ImageIO.read(ByteArrayInputStream(image.png))
        assertNotNull(decoded)
        assertEquals(image.width, decoded.width)
        assertEquals(image.height, decoded.height)
        assertTrue(image.width >= 1_000)
    }

    @Test
    fun `redacts common credentials by default`() {
        val message = """
            POST /login?token=query-secret HTTP/1.1
            Host: example.test
            Authorization: Bearer header-secret
            Cookie: session=cookie-secret
            Content-Type: application/json

            {"password":"body-secret","access_token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}
        """.trimIndent()

        val redacted = EvidenceRenderer.prepareMessage(message, redactSecrets = true, maxBodyCharacters = 4_000)
        assertFalse(redacted.contains("query-secret"))
        assertFalse(redacted.contains("header-secret"))
        assertFalse(redacted.contains("cookie-secret"))
        assertFalse(redacted.contains("body-secret"))
        assertFalse(redacted.contains("eyJhbGci"))
        assertContains(redacted, "[REDACTED]")
    }

    @Test
    fun `truncates only the message body`() {
        val message = "POST / HTTP/1.1\nX-Test: keep\n\n1234567890"
        val prepared = EvidenceRenderer.prepareMessage(message, redactSecrets = false, maxBodyCharacters = 5)
        assertContains(prepared, "X-Test: keep")
        assertContains(prepared, "12345")
        assertFalse(prepared.contains("67890"))
        assertContains(prepared, "5 characters omitted")
    }

    @Test
    fun `renders highlights and numbered annotation callouts`() {
        val image = EvidenceRenderer.render(
            request = "POST /login HTTP/1.1\r\nHost: example.test\r\n\r\n{\"role\":\"admin\"}",
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":200}",
            title = "Annotated evidence",
            redactSecrets = true,
            maxBodyCharacters = 4_000,
            highlights = listOf(
                EvidenceHighlight(match = "role", color = "yellow"),
                EvidenceHighlight(match = "HTTP/1\\.1 200", color = "green", regex = true),
            ),
            annotations = listOf(
                EvidenceAnnotation(match = "admin", label = "Privilege changed", color = "red"),
                EvidenceAnnotation(match = "status.*200", label = "Request succeeded", color = "blue", regex = true),
            ),
        )

        assertEquals(2, image.highlightMatches)
        assertEquals(2, image.annotationMatches)
        assertTrue(image.height > 500)
        assertNotNull(ImageIO.read(ByteArrayInputStream(image.png)))
    }
}
