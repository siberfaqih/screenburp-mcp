package net.portswigger.mcp.evidence

import java.awt.Color
import java.awt.Font
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO

/**
 * Builds a separately labeled annotated derivative from a native capture.
 * The original PNG bytes are never modified; the derivative is a new image
 * with numbered badges on verified boxes plus an explicit caption strip
 * (verdict, per-number legend, ranges). Badge coordinates come only from
 * verified [NumberedBox] placements — never estimated.
 */
object EvidenceOverlay {
    private const val LINE_HEIGHT = 24
    private const val PADDING = 14
    const val BADGE_RADIUS = 12

    fun annotate(
        originalPng: ByteArray,
        captionLines: List<String>,
        title: String = "ANNOTATED DERIVATIVE — verify against the original native capture",
    ): ByteArray = annotateImage(decode(originalPng), listOf(title) + captionLines.take(8))

    /**
     * Full annotated derivative: red boxes + numbered badges drawn on the
     * native pixels, plus caption strip with verdict and a per-number legend.
     * Legend entries correspond 1:1 with [numbered] badge numbers.
     */
    fun annotateNumbered(
        originalPng: ByteArray,
        numbered: List<NumberedBox>,
        captionLines: List<String>,
        legend: List<String>,
        title: String = "ANNOTATED DERIVATIVE — verify against the original native capture",
    ): ByteArray {
        val base = decode(originalPng)
        val graphics = base.createGraphics() as java.awt.Graphics2D
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        for (entry in numbered) {
            val box = entry.box
            graphics.color = BoundingBox.RED
            graphics.stroke = java.awt.BasicStroke(BoundingBox.STROKE)
            graphics.drawRect(
                box.x - BoundingBox.PADDING, box.y - BoundingBox.PADDING,
                box.width + BoundingBox.PADDING * 2, box.height + BoundingBox.PADDING * 2,
            )
            drawBadge(graphics, entry.number, box, base.width, base.height)
        }
        graphics.dispose()
        val legendLines = numbered.mapIndexed { index, entry ->
            "${entry.number}. ${legend.getOrElse(index) { entry.box.label }.take(170)}"
        }
        return annotateImage(base, listOf(title) + captionLines.take(4) + legendLines.take(20))
    }

    private fun drawBadge(
        graphics: java.awt.Graphics2D,
        number: Int,
        box: PlacedBox,
        imageWidth: Int,
        imageHeight: Int,
    ) {
        val r = BADGE_RADIUS
        // Anchor on the box's top-right corner, clamped inside the image.
        val cx = (box.x + box.width + BoundingBox.PADDING).coerceIn(r, imageWidth - r)
        val cy = (box.y - BoundingBox.PADDING).coerceIn(r, imageHeight - r)
        graphics.color = BoundingBox.RED
        graphics.fillOval(cx - r, cy - r, r * 2, r * 2)
        graphics.color = Color.WHITE
        graphics.font = Font(Font.SANS_SERIF, Font.BOLD, 14)
        val text = number.toString()
        val width = graphics.fontMetrics.stringWidth(text)
        graphics.drawString(text, cx - width / 2, cy + 5)
        drawLabelTag(graphics, box.label, cx, cy, imageWidth, imageHeight)
    }

    /**
     * Short text label next to the badge (dark pill, white text — same
     * palette as the caption strip, readable over any editor background).
     * Placed left of the badge, or right when the badge hugs the left edge.
     */
    private fun drawLabelTag(
        graphics: java.awt.Graphics2D,
        label: String,
        badgeCx: Int,
        badgeCy: Int,
        imageWidth: Int,
        imageHeight: Int,
    ) {
        val short = label.take(28).trim().ifBlank { return }
        graphics.font = Font(Font.SANS_SERIF, Font.BOLD, 12)
        val metrics = graphics.fontMetrics
        val textWidth = metrics.stringWidth(short)
        val pad = 6
        val pillH = 20
        val pillW = textWidth + pad * 2
        val toLeft = badgeCx - BADGE_RADIUS - pillW >= 0
        val pillX = if (toLeft) badgeCx - BADGE_RADIUS - pillW else badgeCx + BADGE_RADIUS
        if (pillX + pillW > imageWidth) return
        val pillY = (badgeCy - pillH / 2).coerceIn(0, (imageHeight - pillH).coerceAtLeast(0))
        graphics.color = Color(24, 24, 28)
        graphics.fillRect(pillX, pillY, pillW, pillH)
        graphics.color = Color.WHITE
        graphics.drawString(short, pillX + pad, pillY + 15)
    }

    private fun decode(originalPng: ByteArray): BufferedImage =
        ImageIO.read(ByteArrayInputStream(originalPng))
            ?: throw IllegalArgumentException("Original PNG bytes could not be decoded.")

    private fun annotateImage(image: BufferedImage, lines: List<String>): ByteArray {
        val stripHeight = PADDING * 2 + lines.size * LINE_HEIGHT
        val composed = BufferedImage(image.width, image.height + stripHeight, BufferedImage.TYPE_INT_RGB)
        val graphics = composed.createGraphics()
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        graphics.drawImage(image, 0, 0, null)
        graphics.color = Color(24, 24, 28)
        graphics.fillRect(0, image.height, image.width, stripHeight)
        graphics.color = Color(250, 204, 21)
        graphics.font = Font(Font.SANS_SERIF, Font.BOLD, 15)
        graphics.drawString(lines.first().take(160), PADDING, image.height + PADDING + 16)
        graphics.color = Color(235, 235, 240)
        graphics.font = Font(Font.MONOSPACED, Font.PLAIN, 13)
        lines.drop(1).forEachIndexed { index, line ->
            graphics.drawString(line.take(180), PADDING, image.height + PADDING + 16 + (index + 1) * LINE_HEIGHT)
        }
        graphics.dispose()
        val output = ByteArrayOutputStream()
        check(ImageIO.write(composed, "png", output)) { "No PNG writer is available in this Java runtime" }
        return output.toByteArray()
    }
}
