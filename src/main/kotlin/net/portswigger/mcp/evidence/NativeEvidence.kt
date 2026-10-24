package net.portswigger.mcp.evidence

import burp.api.montoya.MontoyaApi
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import kotlinx.serialization.Serializable

/** Per-side native search terms. Only the first non-blank term per side is
 * applied via the native editor search expression (Montoya supports one
 * active search expression per editor). */
@Serializable
data class CaptureHighlight(
    val request: List<String> = emptyList(),
    val response: List<String> = emptyList(),
)

/**
 * Input for the `burp_capture_evidence` MCP tool.
 *
 * `request_id` selects an actual request-response pair already captured by
 * Burp: a zero-based Proxy history offset (`"123"` or `"proxy:123"`).
 * HTTP messages are never fabricated or regenerated.
 */
@Serializable
data class BurpCaptureEvidence(
    val request_id: String,
    val mode: String = "native_editor",
    val layout: String = "side_by_side",
    val theme: String = "inherit",
    val capture_width: Int = 1920,
    val capture_height: Int = 1080,
    val highlight: CaptureHighlight = CaptureHighlight(),
    val redact_sensitive: Boolean = true,
    val bounding_boxes: Boolean = true,
    val output: String? = null,
    val region_x: Int? = null,
    val region_y: Int? = null,
    val region_width: Int? = null,
    val region_height: Int? = null,
)

enum class CaptureMode { NATIVE_EDITOR, REPEATER }
enum class CaptureLayout { SIDE_BY_SIDE, STACKED }

object NativeEvidence {
    const val MIN_WIDTH = 400
    const val MAX_WIDTH = 3840
    const val MIN_HEIGHT = 300
    const val MAX_HEIGHT = 2160

    fun parseMode(mode: String): CaptureMode = when (mode.lowercase()) {
        "native_editor" -> CaptureMode.NATIVE_EDITOR
        "repeater" -> CaptureMode.REPEATER
        else -> throw IllegalArgumentException(
            "Unsupported mode '$mode'. Supported modes: native_editor, repeater."
        )
    }

    fun parseLayout(layout: String): CaptureLayout = when (layout.lowercase()) {
        "side_by_side" -> CaptureLayout.SIDE_BY_SIDE
        "stacked" -> CaptureLayout.STACKED
        else -> throw IllegalArgumentException(
            "Unsupported layout '$layout'. Supported layouts: side_by_side, stacked."
        )
    }

    fun requireInheritedTheme(theme: String) {
        if (!theme.equals("inherit", ignoreCase = true)) {
            throw UnsupportedOperationException(
                "Theme '$theme' is not supported. Burp theme is always inherited " +
                    "from the user's active Burp Suite theme; use theme 'inherit'."
            )
        }
    }

    fun requireValidDimensions(width: Int, height: Int) {
        if (width !in MIN_WIDTH..MAX_WIDTH || height !in MIN_HEIGHT..MAX_HEIGHT) {
            throw IllegalArgumentException(
                "Capture dimensions ${width}x${height} are out of range. " +
                    "Supported: width $MIN_WIDTH-$MAX_WIDTH, height $MIN_HEIGHT-$MAX_HEIGHT."
            )
        }
    }

    fun requirePngOutput(output: String?) {
        if (output != null && !output.lowercase().endsWith(".png")) {
            throw IllegalArgumentException("Output path must end with '.png': $output")
        }
    }

    /**
     * Resolves [requestId] against live Proxy history. Never synthesizes data.
     *
     * Accepted forms: a zero-based history offset (`"123"`, `"proxy:123"`)
     * or a stable Burp item id (`"id:456"`, matching
     * `ProxyHttpRequestResponse.id()`).
     */
    fun resolveProxyItem(api: MontoyaApi, requestId: String): ProxyHttpRequestResponse {
        val trimmed = requestId.trim()
        if (trimmed.startsWith("id:", ignoreCase = true)) {
            val id = trimmed.drop(3).toIntOrNull()
                ?: throw IllegalArgumentException(
                    "Invalid request_id '$requestId'. Stable ids look like \"id:456\" " +
                        "(see the id field of get_proxy_http_history items)."
                )
            return api.proxy().history().firstOrNull { it.id() == id }
                ?: throw IllegalArgumentException(
                    "No Proxy HTTP history item has stable id $id. " +
                        "Use get_proxy_http_history to list available ids."
                )
        }
        val offset = trimmed.removePrefix("proxy:").toIntOrNull()
            ?: throw IllegalArgumentException(
                "Invalid request_id '$requestId'. Use a zero-based Proxy history " +
                    "offset, e.g. \"123\", or a stable id, e.g. \"id:456\" " +
                    "(see get_proxy_http_history)."
            )
        require(offset >= 0) { "request_id must be zero or greater" }
        return api.proxy().history().asSequence().drop(offset).firstOrNull()
            ?: throw IllegalArgumentException(
                "No Proxy HTTP history item exists at offset $offset. " +
                    "Use get_proxy_http_history to list available offsets."
            )
    }

    fun firstSearchTerm(terms: List<String>): String? =
        terms.firstOrNull { it.isNotBlank() }

    /** Caps for red-box highlight targets derived from `highlight` terms. */
    const val MAX_HIGHLIGHT_BOXES_PER_TERM = 10
    const val MAX_HIGHLIGHT_BOXES_PER_SIDE = 20

    /**
     * Builds red-box [BoxTarget]s for every case-insensitive occurrence of
     * [terms] in [message]. Offsets index the original message; the matched
     * text preserves the original casing. Blank terms, terms longer than 500
     * characters, and terms that are themselves secrets (when
     * [redactSensitive] is on, mirroring the native search-expression
     * filter) are skipped. Results are capped at
     * [MAX_HIGHLIGHT_BOXES_PER_TERM] per term and [MAX_HIGHLIGHT_BOXES_PER_SIDE]
     * total to avoid clutter.
     */
    fun highlightBoxTargets(
        message: String,
        terms: List<String>,
        side: BoxSide,
        redactSensitive: Boolean,
    ): List<BoxTarget> {
        val targets = mutableListOf<BoxTarget>()
        for (term in terms) {
            if (term.isBlank() || term.length !in 1..500) continue
            if (redactSensitive && EvidenceRedaction.redact(term) != term) continue
            var from = 0
            var perTerm = 0
            while (perTerm < MAX_HIGHLIGHT_BOXES_PER_TERM &&
                targets.size < MAX_HIGHLIGHT_BOXES_PER_SIDE &&
                from <= message.length - term.length
            ) {
                val at = message.indexOf(term, from, ignoreCase = true)
                if (at < 0) break
                val text = message.substring(at, at + term.length)
                if (text.length in 1..500) {
                    targets += BoxTarget(side, text, at, BoundingBox.HIGHLIGHT_LABEL)
                    perTerm++
                }
                from = at + maxOf(term.length, 1)
            }
            if (targets.size >= MAX_HIGHLIGHT_BOXES_PER_SIDE) break
        }
        return targets
    }
}
