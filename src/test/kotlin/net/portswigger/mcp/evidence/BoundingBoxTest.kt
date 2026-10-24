package net.portswigger.mcp.evidence

import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.Point
import java.io.ByteArrayInputStream
import javax.imageio.ImageIO
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextArea
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BoundingBoxTest {
    private fun editorPanel(text: String): Triple<JPanel, JTextArea, JScrollPane> {
        val area = JTextArea(text)
        area.isEditable = false
        // Explicit sizes: unrealized panels do not lay out scroll children,
        // so size the text area directly (mirrors a realized viewport).
        area.preferredSize = Dimension(780, 2000)
        area.size = Dimension(780, 2000)
        area.doLayout()
        val scroll = JScrollPane(area)
        scroll.preferredSize = Dimension(800, 600)
        scroll.size = Dimension(800, 600)
        scroll.doLayout()
        scroll.validate()
        val panel = JPanel(BorderLayout())
        panel.add(scroll, BorderLayout.CENTER)
        panel.preferredSize = Dimension(800, 600)
        panel.size = Dimension(800, 600)
        panel.validate()
        panel.doLayout()
        return Triple(panel, area, scroll)
    }

    @Test
    fun `locates text regardless of line ending normalization`() {
        val original = "POST /x HTTP/1.1\r\nHost: y\r\n\r\n{\"url\":\"http://evil.test/poc\"}"
        val (_, area, _) = editorPanel(original)
        val doc = area.document.getText(0, area.document.length)
        val range = BoundingBox.locateInDocument(area, original, "http://evil.test/poc", original.indexOf("http://evil"))
        assertNotNull(range)
        assertEquals("http://evil.test/poc", doc.substring(range!!.first, range.last + 1))
    }

    @Test
    fun `row rects cover multiline ranges`() {
        val (panel, area, _) = editorPanel("line one\nsecond line here\nthird")
        panel.validate()
        val range = BoundingBox.locateInDocument(area, area.text, "one\nsecond", 5)
        assertNotNull(range)
        val rects = BoundingBox.rowRects(area, range!!)
        assertEquals(2, rects.size)
        assertTrue(rects[0].y < rects[1].y)
    }

    @Test
    fun `viewport scroll translates coordinates`() {
        val text = (1..50).joinToString("\n") { "filler line number $it" } + "\nTARGET HERE\n" +
            (1..50).joinToString("\n") { "trailing $it" }
        val (panel, area, scroll) = editorPanel(text)
        val range = BoundingBox.locateInDocument(area, text, "TARGET HERE", text.indexOf("TARGET"))
        assertNotNull(range)
        val rows = BoundingBox.rowRects(area, range!!)
        assertTrue(rows.isNotEmpty())
        // Simulate scroll: shift viewport, translated rect must move up.
        val before = BoundingBox.toImageCoords(area, rows.first(), panel)
        scroll.viewport.viewPosition = Point(0, 200)
        val after = BoundingBox.toImageCoords(area, rows.first(), panel)
        assertEquals(before.x, after.x)
        assertEquals(before.y - 200, after.y)
    }

    @Test
    fun `places and merges boxes end to end`() {
        val request = "POST /m HTTP/1.1\nHost: x\n\n{\"url\":\"http://evil.test/poc\",\"a\":1}"
        val response = "HTTP/1.1 200 OK\n\n{\"echo\":\"http://evil.test/poc\"}"
        val (reqPanel, _, _) = editorPanel(request)
        val (resPanel, _, _) = editorPanel(response)
        val container = JPanel(BorderLayout())
        container.add(reqPanel, BorderLayout.WEST)
        container.preferredSize = Dimension(800, 600)
        container.size = Dimension(800, 600)
        container.validate()
        container.doLayout()

        val placement = BoundingBox.placeBoxes(
            reqPanel, request, resPanel, response, container, 800, 600,
            listOf(
                // Overlapping: payload inside the modified value -> one box.
                BoxTarget(BoxSide.REQUEST, "\"url\":\"http://evil.test/poc\"", request.indexOf("\"url\""), "modified"),
                BoxTarget(BoxSide.REQUEST, "http://evil.test/poc", request.indexOf("http://evil"), "payload"),
                BoxTarget(BoxSide.RESPONSE, "http://evil.test/poc", response.indexOf("http://evil"), "evidence"),
            ),
        )
        assertTrue(placement.notes.isEmpty(), placement.notes.toString())
        val reqBoxes = placement.boxes.filter { it.side == BoxSide.REQUEST }
        assertEquals(1, reqBoxes.size)
        val resBoxes = placement.boxes.filter { it.side == BoxSide.RESPONSE }
        assertEquals(1, resBoxes.size)
    }

    @Test
    fun `missing text is reported not boxed`() {
        val (panel, _, _) = editorPanel("hello world this is a long enough document body")
        val container = JPanel()
        val placement = BoundingBox.placeBoxes(
            panel, "hello world this is a long enough document body", null, null,
            container, 800, 600,
            listOf(BoxTarget(BoxSide.REQUEST, "no-such-text-anywhere", 0, "ghost")),
        )
        assertTrue(placement.boxes.isEmpty())
        assertEquals(1, placement.notes.size)
    }

    @Test
    fun `redaction boxes never merge into outline boxes`() {
        val boxes = BoundingBox.mergeOverlapping(
            listOf(
                PlacedBox(BoxSide.REQUEST, 10, 10, 100, 20, "payload"),
                PlacedBox(BoxSide.REQUEST, 20, 12, 30, 10, BoundingBox.REDACTED_LABEL),
                PlacedBox(BoxSide.REQUEST, 200, 10, 50, 20, "evidence"),
            )
        )
        assertEquals(3, boxes.size)
    }

    @Test
    fun `highlight targets place end to end and draw red`() {
        val request = "POST /mechanic_api HTTP/1.1\nHost: example.test\n\nbody with needle inside"
        val (reqPanel, _, _) = editorPanel(request)
        val container = JPanel(BorderLayout())
        container.add(reqPanel, BorderLayout.CENTER)
        container.preferredSize = Dimension(800, 600)
        container.size = Dimension(800, 600)
        container.validate()
        container.doLayout()

        val targets = NativeEvidence.highlightBoxTargets(
            request, listOf("mechanic_api", "needle"), BoxSide.REQUEST, redactSensitive = false,
        )
        assertEquals(2, targets.size)
        val placement = BoundingBox.placeBoxes(
            reqPanel, request, null, null, container, 800, 600, targets,
        )
        assertTrue(placement.notes.isEmpty(), placement.notes.toString())
        assertEquals(2, placement.boxes.size)

        val image = java.awt.image.BufferedImage(800, 600, java.awt.image.BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        graphics.color = Color.WHITE
        graphics.fillRect(0, 0, 800, 600)
        graphics.dispose()
        val output = java.io.ByteArrayOutputStream()
        ImageIO.write(image, "png", output)
        val boxed = BoundingBox.drawBoxes(output.toByteArray(), placement.boxes)
        val decoded = ImageIO.read(ByteArrayInputStream(boxed))
        assertNotNull(decoded)
        // At least one pure-red pixel must exist on a box border.
        var reds = 0
        for (box in placement.boxes) {
            val edgeX = (box.x - BoundingBox.PADDING).coerceIn(0, decoded.width - 1)
            val midY = (box.y + box.height / 2).coerceIn(0, decoded.height - 1)
            if (decoded.getRGB(edgeX, midY) == Color(255, 0, 0).rgb) reds++
        }
        assertTrue(reds > 0, "expected red box borders in drawn image")
    }

    @Test
    fun `drawn boxes are pure red sharp and transparent inside`() {
        val image = java.awt.image.BufferedImage(200, 100, java.awt.image.BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        graphics.color = Color.WHITE
        graphics.fillRect(0, 0, 200, 100)
        graphics.dispose()
        val output = java.io.ByteArrayOutputStream()
        ImageIO.write(image, "png", output)
        val boxed = BoundingBox.drawBoxes(
            output.toByteArray(), listOf(PlacedBox(BoxSide.REQUEST, 50, 30, 60, 20, "t"))
        )
        val decoded = ImageIO.read(ByteArrayInputStream(boxed))
        assertNotNull(decoded)
        assertEquals(200, decoded.width)
        assertEquals(100, decoded.height)
        // Border: box (50,30,60,20) + 5px padding -> edges at x=45/115, y=25/55.
        assertEquals(Color(255, 0, 0).rgb, decoded.getRGB(60, 25))
        assertEquals(Color(255, 0, 0).rgb, decoded.getRGB(60, 55))
        // Interior untouched (transparent background).
        assertEquals(Color.WHITE.rgb, decoded.getRGB(60, 40))
        // 3px stroke centered on the edge: rows 24-26 and 54-56 red, neighbors white.
        assertEquals(Color(255, 0, 0).rgb, decoded.getRGB(60, 26))
        assertNotEquals(Color(255, 0, 0).rgb, decoded.getRGB(60, 28))
        assertNotEquals(Color(255, 0, 0).rgb, decoded.getRGB(60, 57))
    }
}
