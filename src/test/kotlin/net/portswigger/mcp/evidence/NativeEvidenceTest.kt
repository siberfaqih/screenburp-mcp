package net.portswigger.mcp.evidence

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class NativeEvidenceTest {
    private val api = mockk<MontoyaApi>(relaxed = true)

    @Test
    fun `parses supported modes and layouts`() {
        assertEquals(CaptureMode.NATIVE_EDITOR, NativeEvidence.parseMode("native_editor"))
        assertEquals(CaptureMode.REPEATER, NativeEvidence.parseMode("repeater"))
        assertEquals(CaptureLayout.SIDE_BY_SIDE, NativeEvidence.parseLayout("side_by_side"))
        assertEquals(CaptureLayout.STACKED, NativeEvidence.parseLayout("stacked"))
    }

    @Test
    fun `rejects unsupported modes and layouts explicitly`() {
        assertThrows<IllegalArgumentException> { NativeEvidence.parseMode("browser") }
        assertThrows<IllegalArgumentException> { NativeEvidence.parseLayout("grid") }
    }

    @Test
    fun `rejects non-inherit themes explicitly`() {
        NativeEvidence.requireInheritedTheme("inherit")
        assertThrows<UnsupportedOperationException> { NativeEvidence.requireInheritedTheme("dark") }
        assertThrows<UnsupportedOperationException> { NativeEvidence.requireInheritedTheme("light") }
    }

    @Test
    fun `rejects out-of-range dimensions and non-png output`() {
        NativeEvidence.requireValidDimensions(1920, 1080)
        assertThrows<IllegalArgumentException> { NativeEvidence.requireValidDimensions(100, 1080) }
        assertThrows<IllegalArgumentException> { NativeEvidence.requireValidDimensions(5000, 1080) }
        assertThrows<IllegalArgumentException> { NativeEvidence.requireValidDimensions(1920, 50) }
        NativeEvidence.requirePngOutput(null)
        NativeEvidence.requirePngOutput("evidence/step-01.png")
        assertThrows<IllegalArgumentException> { NativeEvidence.requirePngOutput("evidence/step-01.jpg") }
    }

    @Test
    fun `uses first non-blank highlight term`() {
        assertEquals("abc", NativeEvidence.firstSearchTerm(listOf("", "abc", "def")))
        assertNull(NativeEvidence.firstSearchTerm(listOf("", "  ")))
        assertNull(NativeEvidence.firstSearchTerm(emptyList()))
    }

    @Test
    fun `resolves proxy offsets and rejects unknown ids explicitly`() {
        val proxy = mockk<Proxy>()
        val item = mockk<ProxyHttpRequestResponse>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(item)

        assertEquals(item, NativeEvidence.resolveProxyItem(api, "0"))
        assertEquals(item, NativeEvidence.resolveProxyItem(api, "proxy:0"))
        assertThrows<IllegalArgumentException> { NativeEvidence.resolveProxyItem(api, "7") }
        assertThrows<IllegalArgumentException> { NativeEvidence.resolveProxyItem(api, "not-an-offset") }
        assertThrows<IllegalArgumentException> { NativeEvidence.resolveProxyItem(api, "-1") }
    }

    @Test
    fun `resolves stable burp ids`() {
        val proxy = mockk<Proxy>()
        val item = mockk<ProxyHttpRequestResponse>()
        every { api.proxy() } returns proxy
        every { proxy.history() } returns listOf(item)
        every { item.id() } returns 456

        assertEquals(item, NativeEvidence.resolveProxyItem(api, "id:456"))
        assertThrows<IllegalArgumentException> { NativeEvidence.resolveProxyItem(api, "id:999") }
        assertThrows<IllegalArgumentException> { NativeEvidence.resolveProxyItem(api, "id:abc") }
    }

    @Test
    fun `highlight box targets locate case-insensitive occurrences`() {
        val message = "POST /mechanic_api HTTP/1.1\r\nHost: x\r\n\r\nsee MECHANIC_api here"
        val targets = NativeEvidence.highlightBoxTargets(
            message, listOf("mechanic_api"), BoxSide.REQUEST, redactSensitive = false,
        )
        assertEquals(2, targets.size)
        assertTrue(targets.all { it.side == BoxSide.REQUEST && it.label == BoundingBox.HIGHLIGHT_LABEL })
        for (target in targets) {
            assertEquals(target.text, message.substring(target.approxOffset, target.approxOffset + target.text.length))
        }
    }

    @Test
    fun `highlight box targets skip blanks and cap per side`() {
        val message = "a ".repeat(200)
        val targets = NativeEvidence.highlightBoxTargets(
            message, listOf("", "  ", "a"), BoxSide.RESPONSE, redactSensitive = false,
        )
        assertEquals(NativeEvidence.MAX_HIGHLIGHT_BOXES_PER_TERM, targets.size)
        assertTrue(targets.size <= NativeEvidence.MAX_HIGHLIGHT_BOXES_PER_SIDE)
    }

    @Test
    fun `highlight box targets skip secret terms when redacting`() {
        val secretTerm = "\"password\": \"hunter2\""
        assertTrue(EvidenceRedaction.redact(secretTerm) != secretTerm)
        val message = "POST /login HTTP/1.1\r\n\r\n{\"password\": \"hunter2\"}"
        val redacted = NativeEvidence.highlightBoxTargets(
            message, listOf(secretTerm), BoxSide.REQUEST, redactSensitive = true,
        )
        assertTrue(redacted.isEmpty())
        val unredacted = NativeEvidence.highlightBoxTargets(
            message, listOf(secretTerm), BoxSide.REQUEST, redactSensitive = false,
        )
        assertEquals(1, unredacted.size)
    }
}
