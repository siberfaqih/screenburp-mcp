package net.portswigger.mcp.evidence

import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.awt.Frame
import java.awt.GraphicsEnvironment
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RepeaterCaptureTest {
    @Test
    fun `rejects invalid regions explicitly`() {
        // Zero/negative sizes fail before any screen access, on every platform.
        assertThrows<IllegalArgumentException> { RepeaterCapture.captureRectangle(0, 0, 0, 600) }
        assertThrows<IllegalArgumentException> { RepeaterCapture.captureRectangle(0, 0, 800, -1) }
        assertThrows<IllegalArgumentException> { RepeaterCapture.captureRectangle(0, 0, 5000, 600) }
    }

    @Test
    fun `reports headless environments explicitly instead of simulating`() {
        if (!GraphicsEnvironment.isHeadless()) return
        assertThrows<UnsupportedOperationException> {
            RepeaterCapture.captureRectangle(0, 0, 100, 100)
        }
    }

    @Test
    fun `refuses hidden burp windows instead of capturing something else`() {
        val frame = mockk<Frame>()
        every { frame.isShowing } returns false
        val error = assertThrows<IllegalArgumentException> {
            RepeaterCapture.captureSuiteFrame(frame)
        }
        assertTrue(error.message!!.contains("not visible"))
    }

    @Test
    fun `redaction covers headers json query and jwt shapes`() {
        val message = "POST /login?token=query-secret HTTP/1.1\n" +
            "Host: example.test\n" +
            "Authorization: Bearer header-secret\n" +
            "Cookie: session=cookie-secret\n" +
            "Content-Type: application/json\n\n" +
            "{\"password\":\"body-secret\",\"token\":\"abc\"}\n" +
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
        val redacted = EvidenceRedaction.redact(message)
        assertFalse(redacted.contains("query-secret"))
        assertFalse(redacted.contains("header-secret"))
        assertFalse(redacted.contains("cookie-secret"))
        assertFalse(redacted.contains("body-secret"))
        assertFalse(redacted.contains("eyJhbGci"))
        assertTrue(EvidenceRedaction.looksRedacted(redacted))
    }
}
