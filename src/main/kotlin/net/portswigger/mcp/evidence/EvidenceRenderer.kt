package net.portswigger.mcp.evidence

import java.awt.BasicStroke
import java.awt.Color
import java.awt.Font
import java.awt.Graphics2D
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import javax.imageio.ImageIO
import kotlinx.serialization.Serializable

@Serializable
data class EvidenceHighlight(
    val match: String,
    val color: String = "yellow",
    val regex: Boolean = false,
    val caseSensitive: Boolean = false,
)

@Serializable
data class EvidenceAnnotation(
    val match: String,
    val label: String,
    val color: String = "red",
    val regex: Boolean = false,
    val caseSensitive: Boolean = false,
)

data class EvidenceImage(
    val png: ByteArray,
    val width: Int,
    val height: Int,
    val highlightMatches: Int,
    val annotationMatches: Int,
)

/**
 * Renders HTTP messages directly to a BufferedImage. This intentionally avoids
 * Robot, Swing components, the clipboard, and the currently focused Burp tab,
 * so it also works when Burp has no visible window.
 */
object EvidenceRenderer {
    private const val WIDTH = 1400
    private const val OUTER_PADDING = 28
    private const val PANEL_PADDING = 16
    private const val MAX_RENDERED_LINES = 700
    private const val MAX_HIGHLIGHTS = 25
    private const val MAX_ANNOTATIONS = 20
    private const val CALLOUT_GUTTER = 170

    private val background = Color(245, 246, 248)
    private val panel = Color.WHITE
    private val border = Color(218, 220, 226)
    private val text = Color(31, 31, 35)
    private val muted = Color(100, 102, 110)
    private val requestColor = Color(194, 65, 12)
    private val responseColor = Color(29, 78, 216)

    fun render(
        request: String,
        response: String?,
        title: String?,
        redactSecrets: Boolean,
        maxBodyCharacters: Int,
        highlights: List<EvidenceHighlight> = emptyList(),
        annotations: List<EvidenceAnnotation> = emptyList(),
    ): EvidenceImage {
        val safeLimit = maxBodyCharacters.coerceIn(0, 20_000)
        val normalizedRequest = prepareMessage(request, redactSecrets, safeLimit)
        val normalizedResponse = prepareMessage(response ?: "<No response>", redactSecrets, safeLimit)

        val titleFont = Font(Font.SANS_SERIF, Font.BOLD, 25)
        val metadataFont = Font(Font.SANS_SERIF, Font.PLAIN, 16)
        val headingFont = Font(Font.SANS_SERIF, Font.BOLD, 17)
        val monoFont = Font(Font.MONOSPACED, Font.PLAIN, 14)

        val metricsImage = BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB)
        val metricsGraphics = metricsImage.createGraphics()
        val monoMetrics = metricsGraphics.getFontMetrics(monoFont)
        val maxTextWidth = WIDTH - (OUTER_PADDING * 2) - (PANEL_PADDING * 2) - CALLOUT_GUTTER
        val requestLines = wrap(normalizedRequest, monoMetrics, maxTextWidth)
        val responseLines = wrap(normalizedResponse, monoMetrics, maxTextWidth)
        val compiledHighlights = highlights.take(MAX_HIGHLIGHTS).filter { it.match.isNotEmpty() }.map(::compileHighlight)
        val compiledAnnotations = annotations.take(MAX_ANNOTATIONS).filter { it.match.isNotEmpty() && it.label.isNotBlank() }
            .mapIndexed { index, annotation -> compileAnnotation(index + 1, annotation) }
        val requestAnalysis = analyze(requestLines, compiledHighlights, compiledAnnotations, emptySet())
        val responseAnalysis = analyze(responseLines, compiledHighlights, compiledAnnotations, requestAnalysis.matchedAnnotations)
        val matchedAnnotationNumbers = requestAnalysis.matchedAnnotations + responseAnalysis.matchedAnnotations
        val matchedAnnotations = compiledAnnotations.filter { it.number in matchedAnnotationNumbers }
        metricsGraphics.dispose()

        val lineHeight = monoMetrics.height + 3
        val headingHeight = 38
        val titleHeight = 34
        val metadataHeight = 28
        val footerHeight = 34
        val annotationLegendHeight = if (matchedAnnotations.isEmpty()) 0 else 44 + matchedAnnotations.size * 30 + PANEL_PADDING
        val requestPanelHeight = requestLines.size * lineHeight + PANEL_PADDING * 2
        val responsePanelHeight = responseLines.size * lineHeight + PANEL_PADDING * 2
        val gap = 14
        val height = OUTER_PADDING + titleHeight + metadataHeight +
            headingHeight + requestPanelHeight + gap +
            headingHeight + responsePanelHeight + gap + annotationLegendHeight +
            (if (annotationLegendHeight > 0) gap else 0) + footerHeight + OUTER_PADDING

        val image = BufferedImage(WIDTH, height, BufferedImage.TYPE_INT_RGB)
        val graphics = image.createGraphics()
        configure(graphics)
        graphics.color = background
        graphics.fillRect(0, 0, WIDTH, height)

        var y = OUTER_PADDING
        graphics.font = titleFont
        graphics.color = text
        graphics.drawString(title?.takeIf { it.isNotBlank() } ?: "Burp Pentest Evidence", OUTER_PADDING, y + 25)
        y += titleHeight

        val requestLine = normalizedRequest.lineSequence().firstOrNull().orEmpty()
        val responseLine = normalizedResponse.lineSequence().firstOrNull().orEmpty()
        graphics.font = metadataFont
        graphics.color = muted
        graphics.drawString("$requestLine  •  $responseLine", OUTER_PADDING, y + 19)
        y += metadataHeight

        y = drawSection(graphics, "REQUEST", requestLines, requestAnalysis, y, requestColor, headingFont, monoFont, lineHeight)
        y += gap
        y = drawSection(graphics, "RESPONSE", responseLines, responseAnalysis, y, responseColor, headingFont, monoFont, lineHeight)
        y += gap

        if (matchedAnnotations.isNotEmpty()) {
            y = drawAnnotationLegend(graphics, matchedAnnotations, y, headingFont, metadataFont)
            y += gap
        }

        graphics.font = metadataFont
        graphics.color = muted
        val redactionLabel = if (redactSecrets) "secrets redacted" else "unredacted"
        val matchLabel = "${requestAnalysis.highlightMatches + responseAnalysis.highlightMatches} highlights  •  ${matchedAnnotations.size} callouts"
        graphics.drawString("Generated headlessly by ScreenBurp MCP  •  $redactionLabel  •  $matchLabel", OUTER_PADDING, y + 22)
        graphics.dispose()

        val output = ByteArrayOutputStream()
        check(ImageIO.write(image, "png", output)) { "No PNG writer is available in this Java runtime" }
        return EvidenceImage(
            output.toByteArray(), image.width, image.height,
            requestAnalysis.highlightMatches + responseAnalysis.highlightMatches,
            matchedAnnotations.size,
        )
    }

    internal fun prepareMessage(message: String, redactSecrets: Boolean, maxBodyCharacters: Int): String {
        var normalized = message.replace("\r\n", "\n").replace('\r', '\n')
        if (redactSecrets) {
            normalized = EvidenceRedaction.redact(normalized)
        }

        val separator = normalized.indexOf("\n\n")
        if (separator < 0) return normalized

        val headers = normalized.substring(0, separator)
        val body = normalized.substring(separator + 2)
        val limitedBody = if (body.length <= maxBodyCharacters) {
            body
        } else {
            body.take(maxBodyCharacters) + "\n… [body truncated; ${body.length - maxBodyCharacters} characters omitted]"
        }
        return "$headers\n\n$limitedBody"
    }

    private fun wrap(text: String, metrics: java.awt.FontMetrics, maxWidth: Int): List<String> {
        val wrapped = mutableListOf<String>()
        for (sourceLine in text.lineSequence()) {
            if (sourceLine.isEmpty()) {
                wrapped += ""
                continue
            }
            var remaining = sourceLine
            while (metrics.stringWidth(remaining) > maxWidth) {
                var low = 1
                var high = remaining.length
                while (low < high) {
                    val middle = (low + high + 1) / 2
                    if (metrics.stringWidth(remaining.substring(0, middle)) <= maxWidth) low = middle else high = middle - 1
                }
                wrapped += remaining.substring(0, low)
                remaining = remaining.substring(low)
            }
            wrapped += remaining
            if (wrapped.size >= MAX_RENDERED_LINES) {
                wrapped += "… [rendered line limit reached]"
                return wrapped
            }
        }
        return wrapped.ifEmpty { listOf("") }
    }

    private fun drawSection(
        graphics: Graphics2D,
        label: String,
        lines: List<String>,
        analysis: SectionAnalysis,
        y: Int,
        accent: Color,
        headingFont: Font,
        monoFont: Font,
        lineHeight: Int,
    ): Int {
        val x = OUTER_PADDING
        val width = WIDTH - OUTER_PADDING * 2
        val headingHeight = 38
        graphics.color = accent
        graphics.fillRoundRect(x, y, width, headingHeight, 12, 12)
        graphics.font = headingFont
        graphics.color = Color.WHITE
        graphics.drawString(label, x + PANEL_PADDING, y + 25)

        val panelY = y + headingHeight + 6
        val panelHeight = lines.size * lineHeight + PANEL_PADDING * 2
        graphics.color = panel
        graphics.fillRoundRect(x, panelY, width, panelHeight, 12, 12)
        graphics.color = border
        graphics.stroke = BasicStroke(1f)
        graphics.drawRoundRect(x, panelY, width, panelHeight, 12, 12)

        graphics.font = monoFont
        graphics.color = text
        var textY = panelY + PANEL_PADDING + graphics.fontMetrics.ascent
        for ((lineIndex, line) in lines.withIndex()) {
            val baseline = textY
            for (range in analysis.highlights[lineIndex].orEmpty()) {
                val prefixWidth = graphics.fontMetrics.stringWidth(line.substring(0, range.first))
                val matchWidth = graphics.fontMetrics.stringWidth(line.substring(range.first, range.last + 1)).coerceAtLeast(3)
                graphics.color = range.color
                graphics.fillRoundRect(
                    x + PANEL_PADDING + prefixWidth - 2,
                    baseline - graphics.fontMetrics.ascent - 2,
                    matchWidth + 4,
                    lineHeight,
                    6,
                    6,
                )
            }
            graphics.color = text
            graphics.drawString(line, x + PANEL_PADDING, textY)
            for ((calloutIndex, callout) in analysis.callouts[lineIndex].orEmpty().take(6).withIndex()) {
                val centerX = x + width - PANEL_PADDING - 12 - calloutIndex * 26
                val centerY = baseline - graphics.fontMetrics.ascent / 2
                graphics.color = callout.color
                graphics.fillOval(centerX - 11, centerY - 11, 22, 22)
                graphics.color = Color.WHITE
                graphics.font = Font(Font.SANS_SERIF, Font.BOLD, 12)
                val number = callout.number.toString()
                val numberWidth = graphics.fontMetrics.stringWidth(number)
                graphics.drawString(number, centerX - numberWidth / 2, centerY + 5)
                graphics.font = monoFont
            }
            textY += lineHeight
        }
        return panelY + panelHeight
    }

    private fun drawAnnotationLegend(
        graphics: Graphics2D,
        annotations: List<CompiledAnnotation>,
        y: Int,
        headingFont: Font,
        metadataFont: Font,
    ): Int {
        val x = OUTER_PADDING
        val width = WIDTH - OUTER_PADDING * 2
        val height = 44 + annotations.size * 30 + PANEL_PADDING
        graphics.color = panel
        graphics.fillRoundRect(x, y, width, height, 12, 12)
        graphics.color = border
        graphics.drawRoundRect(x, y, width, height, 12, 12)
        graphics.font = headingFont
        graphics.color = text
        graphics.drawString("ANNOTATIONS", x + PANEL_PADDING, y + 27)
        var rowY = y + 51
        for (annotation in annotations) {
            val centerX = x + PANEL_PADDING + 11
            graphics.color = annotation.color
            graphics.fillOval(centerX - 11, rowY - 15, 22, 22)
            graphics.color = Color.WHITE
            graphics.font = Font(Font.SANS_SERIF, Font.BOLD, 12)
            val number = annotation.number.toString()
            val numberWidth = graphics.fontMetrics.stringWidth(number)
            graphics.drawString(number, centerX - numberWidth / 2, rowY)
            graphics.font = metadataFont
            graphics.color = text
            graphics.drawString(annotation.label.take(160), centerX + 22, rowY)
            rowY += 30
        }
        return y + height
    }

    private fun compileHighlight(highlight: EvidenceHighlight): CompiledHighlight = CompiledHighlight(
        pattern = compilePattern(highlight.match, highlight.regex, highlight.caseSensitive),
        color = parseColor(highlight.color, 120),
    )

    private fun compileAnnotation(number: Int, annotation: EvidenceAnnotation): CompiledAnnotation = CompiledAnnotation(
        number = number,
        pattern = compilePattern(annotation.match, annotation.regex, annotation.caseSensitive),
        label = annotation.label,
        color = parseColor(annotation.color, 255),
    )

    private fun compilePattern(match: String, regex: Boolean, caseSensitive: Boolean): Regex {
        val expression = if (regex) match else Regex.escape(match)
        val options = if (caseSensitive) emptySet() else setOf(RegexOption.IGNORE_CASE)
        return Regex(expression, options)
    }

    private fun analyze(
        lines: List<String>,
        highlights: List<CompiledHighlight>,
        annotations: List<CompiledAnnotation>,
        alreadyMatchedAnnotations: Set<Int>,
    ): SectionAnalysis {
        val ranges = mutableMapOf<Int, MutableList<HighlightRange>>()
        val callouts = mutableMapOf<Int, MutableList<CompiledAnnotation>>()
        val matchedAnnotations = alreadyMatchedAnnotations.toMutableSet()
        var highlightMatches = 0
        for ((lineIndex, line) in lines.withIndex()) {
            for (highlight in highlights) {
                for (match in highlight.pattern.findAll(line).filter { it.range.first <= it.range.last }) {
                    ranges.getOrPut(lineIndex) { mutableListOf() } += HighlightRange(match.range, highlight.color)
                    highlightMatches++
                }
            }
            for (annotation in annotations) {
                if (annotation.number !in matchedAnnotations && annotation.pattern.containsMatchIn(line)) {
                    callouts.getOrPut(lineIndex) { mutableListOf() } += annotation
                    matchedAnnotations += annotation.number
                }
            }
        }
        return SectionAnalysis(ranges, callouts, matchedAnnotations, highlightMatches)
    }

    private fun parseColor(name: String, alpha: Int): Color {
        val rgb = when (name.lowercase()) {
            "red" -> 0xDC2626
            "orange" -> 0xEA580C
            "green" -> 0x16A34A
            "blue" -> 0x2563EB
            "purple" -> 0x9333EA
            "cyan" -> 0x0891B2
            "pink" -> 0xDB2777
            "yellow" -> 0xFACC15
            else -> name.removePrefix("#").takeIf { it.matches(Regex("[0-9a-fA-F]{6}")) }?.toInt(16) ?: 0xFACC15
        }
        return Color((rgb shr 16) and 0xff, (rgb shr 8) and 0xff, rgb and 0xff, alpha)
    }

    private data class CompiledHighlight(val pattern: Regex, val color: Color)
    private data class CompiledAnnotation(val number: Int, val pattern: Regex, val label: String, val color: Color)
    private data class HighlightRange(val range: IntRange, val color: Color) {
        val first get() = range.first
        val last get() = range.last
    }
    private data class SectionAnalysis(
        val highlights: Map<Int, List<HighlightRange>>,
        val callouts: Map<Int, List<CompiledAnnotation>>,
        val matchedAnnotations: Set<Int>,
        val highlightMatches: Int,
    )

    private fun configure(graphics: Graphics2D) {
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        graphics.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
    }
}
