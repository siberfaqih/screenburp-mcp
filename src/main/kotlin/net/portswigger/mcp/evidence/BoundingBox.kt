package net.portswigger.mcp.evidence

import java.awt.Color
import java.awt.Component
import java.awt.Container
import java.awt.Graphics2D
import java.awt.Rectangle
import java.awt.BasicStroke
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import javax.swing.JViewport
import javax.swing.SwingUtilities
import javax.swing.text.JTextComponent
import javax.swing.text.Utilities

/** Which editor subtree a box target belongs to. */
enum class BoxSide { REQUEST, RESPONSE }

/** A box request: exact [text] located near [approxOffset] in the original message. */
data class BoxTarget(
    val side: BoxSide,
    val text: String,
    val approxOffset: Int,
    val label: String,
    val detail: String = "",
)

/** A placed box in capture-image pixel coordinates. */
data class PlacedBox(
    val side: BoxSide,
    val x: Int,
    val y: Int,
    val width: Int,
    val height: Int,
    val label: String,
    val detail: String = "",
)

/** A placed box with its legend number (1-based). */
data class NumberedBox(
    val box: PlacedBox,
    val number: Int,
)

data class BoxPlacement(
    val boxes: List<PlacedBox>,
    val notes: List<String>,
)

/**
 * Automatic red bounding boxes computed from verified Swing text geometry.
 *
 * Coordinates come exclusively from [JTextComponent.modelToView2D] on the
 * live, realized editor hierarchy, translated into capture-image pixels via
 * the enclosing viewport position. Nothing is estimated: any text that
 * cannot be located and verified in the editor document is reported in
 * [BoxPlacement.notes] and gets no box.
 *
 * Style: #FF0000, 3 px stroke, sharp corners, 5 px padding, transparent
 * background, no effects.
 */
object BoundingBox {
    val RED = Color(0xFF, 0x00, 0x00)
    const val STROKE = 3f
    const val PADDING = 5
    /** Label marking pixel-redaction boxes (black fill, never outlines). */
    const val REDACTED_LABEL = "redacted"
    /** Label marking red-box highlight outlines (3px #FF0000, never filled). */
    const val HIGHLIGHT_LABEL = "highlight"

    /**
     * Numbers boxes deterministically (request top-to-bottom, then response)
     * so badges, legend, and metadata always agree.
     */
    fun numberBoxes(boxes: List<PlacedBox>): List<NumberedBox> =
        boxes.sortedWith(compareBy({ it.side.ordinal }, { it.y }, { it.x }))
            .mapIndexed { index, box -> NumberedBox(box, index + 1) }

    fun findTextComponents(root: Component): List<JTextComponent> {
        val found = mutableListOf<JTextComponent>()
        fun visit(component: Component) {
            // No isShowing requirement: off-screen realized hierarchies and
            // headless test panels must both work. Candidates are filtered by
            // verified document content below.
            if (component is JTextComponent) found += component
            if (component is Container) {
                for (child in component.components) visit(child)
            }
        }
        visit(root)
        return found
    }

    /**
     * Locates [text] in [component]'s document near the original-message
     * offset [approxOffset], tolerating \r\n -> \n normalization. Returns
     * the verified document range or null.
     */
    fun locateInDocument(
        component: JTextComponent,
        originalText: String,
        text: String,
        approxOffset: Int,
    ): IntRange? {
        if (text.isEmpty()) return null
        val doc = try {
            component.document.getText(0, component.document.length)
        } catch (_: Exception) {
            return null
        }
        // Map the original offset into document space. Some documents
        // normalize \r\n to \n (each \r skipped); others keep the raw bytes
        // (identity mapping). Detect, never assume.
        val normalized = !doc.contains('\r')
        var docApprox = approxOffset.coerceIn(0, originalText.length)
        if (normalized) {
            var i = 0
            var skipped = 0
            while (i < docApprox && i < originalText.length) {
                if (originalText[i] == '\r' && i + 1 < originalText.length && originalText[i + 1] == '\n') skipped++
                i++
            }
            docApprox = (docApprox - skipped).coerceIn(0, doc.length)
        } else {
            docApprox = docApprox.coerceIn(0, doc.length)
        }
        // Exact hit at the mapped offset first.
        if (doc.regionMatches(docApprox, text, 0, text.length)) {
            return docApprox until docApprox + text.length
        }
        // Otherwise the nearest verified occurrence within a window.
        val windowStart = (docApprox - 2000).coerceAtLeast(0)
        val windowEnd = (docApprox + 2000).coerceAtMost(doc.length)
        var best: IntRange? = null
        var bestDistance = Int.MAX_VALUE
        var at = doc.indexOf(text, windowStart)
        while (at >= 0 && at + text.length <= windowEnd) {
            val distance = kotlin.math.abs(at - docApprox)
            if (distance < bestDistance) {
                bestDistance = distance
                best = at until at + text.length
            }
            if (distance == 0) break
            at = doc.indexOf(text, at + 1)
        }
        return best
    }

    /**
     * Per-row rectangles covering [docRange] (inclusive end, as produced by
     * [locateInDocument]), in the text component's own coordinate space.
     */
    fun rowRects(component: JTextComponent, docRange: IntRange): List<Rectangle> {
        val rects = mutableListOf<Rectangle>()
        try {
            var offset = docRange.first.coerceIn(0, component.document.length)
            val end = (docRange.last + 1).coerceIn(0, component.document.length)
            if (offset >= end) return emptyList()
            var guard = 0
            while (offset < end && guard++ < 5000) {
                val rowStart = Utilities.getRowStart(component, offset).coerceAtLeast(0)
                val rowEnd = Utilities.getRowEnd(component, offset).coerceAtLeast(0)
                val segStart = maxOf(offset, rowStart)
                val segEnd = minOf(rowEnd, end)
                if (segEnd > segStart) {
                    val startRect = component.modelToView2D(segStart).bounds
                    val lastRect = component.modelToView2D(segEnd - 1).bounds
                    val x = minOf(startRect.x, lastRect.x)
                    val right = maxOf(startRect.x + startRect.width, lastRect.x + lastRect.width)
                    rects += Rectangle(x, startRect.y, (right - x).coerceAtLeast(2), startRect.height.coerceAtLeast(2))
                }
                // Guarantee forward progress even for degenerate views.
                offset = if (rowEnd > offset) minOf(rowEnd, end) else minOf(offset + 1, end)
            }
        } catch (_: Exception) {
            return emptyList()
        }
        return rects
    }

    /**
     * Translates a text-component rectangle into capture-image pixels. The
     * enclosing viewport positions its view at the negative view position,
     * so the bounds chain already encodes scrolling — no manual adjustment.
     */
    fun toImageCoords(component: JTextComponent, rect: Rectangle, container: Component): Rectangle =
        SwingUtilities.convertRectangle(component, Rectangle(rect), container)

    /**
     * Places boxes for [targets] inside the editor subtrees. Must run on the
     * EDT while the realized hierarchy is alive. Returns placed boxes plus
     * explicit notes for anything skipped.
     */
    fun placeBoxes(
        requestRoot: Component,
        requestText: String,
        responseRoot: Component?,
        responseText: String?,
        container: Component,
        imageWidth: Int,
        imageHeight: Int,
        targets: List<BoxTarget>,
    ): BoxPlacement {
        val boxes = mutableListOf<PlacedBox>()
        val notes = mutableListOf<String>()
        for (target in targets) {
            val root = if (target.side == BoxSide.REQUEST) requestRoot else responseRoot
            val original = if (target.side == BoxSide.REQUEST) requestText else responseText
            if (root == null || original == null) {
                notes += "${target.label}: no ${target.side.name.lowercase()} editor component"
                continue
            }
            val components = findTextComponents(root)
            if (components.isEmpty()) {
                notes += "${target.label}: no text component found in ${target.side.name.lowercase()} editor"
                continue
            }
            // Prefer the component whose document actually contains the text.
            var placed = false
            val byLength = components.sortedByDescending {
                runCatching { it.document.length }.getOrDefault(0)
            }
            for (component in byLength) {
                val doc = runCatching { component.document.getText(0, component.document.length) }.getOrNull()
                    ?: continue
                // Component must hold message-like content, not just chrome (search bars).
                if (doc.length < 20) continue
                val range = locateInDocument(component, original, target.text, target.approxOffset)
                    ?: continue
                val rows = rowRects(component, range)
                if (rows.isEmpty()) continue
                // One enclosing rect per match for readability.
                var union = rows.first()
                for (row in rows.drop(1)) union = union.union(row)
                val image = toImageCoords(component, union, container)
                if (image.width <= 0 || image.height <= 0) continue
                // Clip to the captured image; note when partially outside.
                val clipped = image.intersection(Rectangle(0, 0, imageWidth, imageHeight))
                if (clipped.isEmpty) {
                    notes += "${target.label}: text is outside the captured viewport, no box drawn"
                    placed = true
                    break
                }
                if (clipped != image) notes += "${target.label}: partially outside viewport, box clipped"
                boxes += PlacedBox(target.side, clipped.x, clipped.y, clipped.width, clipped.height, target.label, target.detail)
                placed = true
                break
            }
            if (!placed) notes += "${target.label}: text not verified in editor document, no box drawn"
        }
        return BoxPlacement(mergeOverlapping(boxes), notes)
    }

    /**
     * Unions overlapping boxes on the same side (e.g. a payload inside an
     * already-boxed modified parameter yields one box). Redaction boxes
     * never merge into outline boxes (or vice versa) so secrets keep their
     * black fill even when overlapped by a highlight.
     */
    fun mergeOverlapping(boxes: List<PlacedBox>): List<PlacedBox> {
        fun isRedaction(box: PlacedBox) = box.label == REDACTED_LABEL
        val remaining = boxes.toMutableList()
        val merged = mutableListOf<PlacedBox>()
        while (remaining.isNotEmpty()) {
            var current = remaining.removeAt(0)
            var grown = true
            while (grown) {
                grown = false
                val it = remaining.iterator()
                while (it.hasNext()) {
                    val other = it.next()
                    if (other.side != current.side) continue
                    if (isRedaction(other) != isRedaction(current)) continue
                    if (padded(current).intersects(padded(other))) {
                        val union = current.toRect().union(other.toRect())
                        current = current.copy(
                            x = union.x, y = union.y, width = union.width, height = union.height,
                            label = current.label,
                        )
                        it.remove()
                        grown = true
                    }
                }
            }
            merged += current
        }
        return merged
    }

    private fun PlacedBox.toRect() = Rectangle(x, y, width, height)
    private fun padded(box: PlacedBox) =
        Rectangle(box.x - PADDING, box.y - PADDING, box.width + PADDING * 2, box.height + PADDING * 2)

    /** Draws boxes onto a copy; the input bytes are never modified. */
    fun drawBoxes(originalPng: ByteArray, boxes: List<PlacedBox>): ByteArray {
        val original = javax.imageio.ImageIO.read(java.io.ByteArrayInputStream(originalPng))
            ?: throw IllegalArgumentException("Original PNG bytes could not be decoded.")
        val image = BufferedImage(original.width, original.height, BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics() as Graphics2D
        graphics.drawImage(original, 0, 0, null)
        graphics.color = RED
        graphics.stroke = BasicStroke(STROKE)
        for (box in boxes) {
            graphics.drawRect(box.x - PADDING, box.y - PADDING, box.width + PADDING * 2, box.height + PADDING * 2)
        }
        graphics.dispose()
        val output = ByteArrayOutputStream()
        check(ImageIO.write(image, "png", output)) { "No PNG writer is available in this Java runtime" }
        return output.toByteArray()
    }

    /**
     * Blacks out secret spans on a copy for pixel redaction. The editors
     * always show the raw message; secrets are covered after capture.
     */
    fun drawRedactions(originalPng: ByteArray, boxes: List<PlacedBox>): ByteArray {
        val original = javax.imageio.ImageIO.read(java.io.ByteArrayInputStream(originalPng))
            ?: throw IllegalArgumentException("Original PNG bytes could not be decoded.")
        val image = BufferedImage(original.width, original.height, BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics() as Graphics2D
        graphics.drawImage(original, 0, 0, null)
        graphics.color = Color.BLACK
        for (box in boxes) {
            graphics.fillRect(box.x - 2, box.y - 2, box.width + 4, box.height + 4)
        }
        graphics.dispose()
        val output = ByteArrayOutputStream()
        check(ImageIO.write(image, "png", output)) { "No PNG writer is available in this Java runtime" }
        return output.toByteArray()
    }
}
