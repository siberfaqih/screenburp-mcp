package net.portswigger.mcp.evidence

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.UserInterface
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import io.mockk.*
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NativeEditorCaptureTest {
    @Test
    fun `split pane honors layout orientation`() {
        val left = JPanel()
        val right = JPanel()
        assertEquals(
            JSplitPane.HORIZONTAL_SPLIT,
            NativeEditorCapture.buildSplitPane(left, right, CaptureLayout.SIDE_BY_SIDE).orientation
        )
        assertEquals(
            JSplitPane.VERTICAL_SPLIT,
            NativeEditorCapture.buildSplitPane(left, right, CaptureLayout.STACKED).orientation
        )
    }

    @Test
    fun `painting swing components produces a valid png at requested dimensions`() {
        val left = JPanel().apply { add(JLabel("GET /mechanic_api HTTP/1.1")) }
        val right = JPanel().apply { add(JLabel("HTTP/1.1 200 OK")) }
        val split = NativeEditorCapture.buildSplitPane(left, right, CaptureLayout.SIDE_BY_SIDE)

        val image = NativeEditorCapture.paintToImage(split, 800, 600)

        assertEquals(800, image.width)
        assertEquals(600, image.height)
        val png = NativeEditorCapture.encodePng(image)
        assertTrue(
            png.take(8).toByteArray().contentEquals(
                byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)
            )
        )
        val decoded = ImageIO.read(ByteArrayInputStream(png))
        assertNotNull(decoded)
        assertEquals(800, decoded.width)
        assertEquals(600, decoded.height)
    }

    @Test
    fun `capture wires native editors with exact messages and search terms`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val ui = mockk<UserInterface>(relaxed = true)
        val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
        val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
        val request = mockk<HttpRequest>(relaxed = true)
        val response = mockk<HttpResponse>(relaxed = true)
        every { api.userInterface() } returns ui
        every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
        every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
        every { requestEditor.uiComponent() } returns JPanel().apply { add(JLabel("req")) }
        every { responseEditor.uiComponent() } returns JPanel().apply { add(JLabel("res")) }

        val result = NativeEditorCapture.capture(
            api, request, response, 800, 600,
            CaptureLayout.SIDE_BY_SIDE, "mechanic_api", "HTTP/1.1 200",
        )

        // Exact message objects reach the native editors: never regenerated.
        verify(exactly = 1) { requestEditor.setRequest(request) }
        verify(exactly = 1) { responseEditor.setResponse(response) }
        verify(exactly = 1) { requestEditor.setSearchExpression("mechanic_api") }
        verify(exactly = 1) { responseEditor.setSearchExpression("HTTP/1.1 200") }
        verify(exactly = 1) { ui.applyThemeToComponent(any()) }
        assertEquals(800, result.width)
        assertEquals(600, result.height)
        assertEquals("mechanic_api", result.requestSearchApplied)
        assertEquals("HTTP/1.1 200", result.responseSearchApplied)
        assertNotNull(ImageIO.read(ByteArrayInputStream(result.png)))
        assertTrue(result.png.isNotEmpty())
    }

    @Test
    fun `capture without response still produces a valid image`() {        val api = mockk<MontoyaApi>(relaxed = true)
        val ui = mockk<UserInterface>(relaxed = true)
        val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
        val request = mockk<HttpRequest>(relaxed = true)
        every { api.userInterface() } returns ui
        every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
        every { requestEditor.uiComponent() } returns JPanel().apply { add(JLabel("req")) }

        val result = NativeEditorCapture.capture(
            api, request, null, 800, 600, CaptureLayout.STACKED, null, null,
        )

        assertEquals(800, result.width)
        assertNotNull(ImageIO.read(ByteArrayInputStream(result.png)))
    }

    @Test
    fun `caret placement is verified by read-back and clamped`() {
        val editor = mockk<burp.api.montoya.ui.editor.Editor>()
        every { editor.setCaretPosition(any()) } just io.mockk.runs
        every { editor.caretPosition() } returns 42

        val ok = NativeEditorCapture.applyCaret(editor, 100, 42)
        assertEquals(CaretPlacement(42, 42, true), ok)

        val clamped = NativeEditorCapture.applyCaret(editor, 100, 500)
        assertEquals(false, clamped.verified)
        verify(exactly = 1) { editor.setCaretPosition(100) }
    }

    @Test
    fun `capture scrolls editors to region offsets`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val ui = mockk<UserInterface>(relaxed = true)
        val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
        val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
        val request = mockk<HttpRequest>(relaxed = true)
        val response = mockk<HttpResponse>(relaxed = true)
        every { api.userInterface() } returns ui
        every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
        every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
        every { requestEditor.uiComponent() } returns JPanel()
        every { responseEditor.uiComponent() } returns JPanel()
        every { request.toString() } returns "GET / HTTP/1.1\n\n"
        every { response.toString() } returns "HTTP/1.1 200 OK\n\n0123456789"
        val caretSlot = slot<Int>()
        every { responseEditor.setCaretPosition(capture(caretSlot)) } just runs
        every { responseEditor.caretPosition() } answers { caretSlot.captured }

        val result = NativeEditorCapture.capture(
            api, request, response, 800, 600,
            CaptureLayout.SIDE_BY_SIDE, null, null,
            requestCaret = null, responseCaret = 25,
        )

        assertEquals(null, result.requestCaret)
        assertEquals(CaretPlacement(25, 25, true), result.responseCaret)
    }
}
