package net.portswigger.mcp.evidence

import kotlinx.serialization.Serializable

/**
 * Input for the `burp_diff_evidence` MCP tool.
 *
 * Compares [baseline_id] and [request_id] Proxy history pairs, identifies
 * the submitted payload (via [payload_hint] or the largest verifiable
 * change), locates verified response evidence for [objective], and captures
 * native + annotated-derivative screenshots. A valid baseline is mandatory:
 * modifications are never inferred without one.
 */
@Serializable
data class BurpDiffEvidence(
    val baseline_id: String,
    val request_id: String,
    val objective: String,
    val payload_hint: String? = null,
    val evidence_hint: String? = null,
    val layout: String = "side_by_side",
    val capture_width: Int = 1920,
    val capture_height: Int = 1080,
    val highlight_matches: Boolean = true,
    val redact_sensitive: Boolean = true,
    val bounding_boxes: Boolean = true,
    val box_labels: Boolean = true,
    val output_prefix: String? = null,
)

object DiffEvidence {
    fun validate(input: BurpDiffEvidence) {
        if (input.baseline_id.trim() == input.request_id.trim()) {
            throw IllegalArgumentException("baseline_id and request_id must differ.")
        }
        if (input.objective.isBlank()) {
            throw IllegalArgumentException("objective must describe what the evidence should demonstrate.")
        }
        NativeEvidence.requireValidDimensions(input.capture_width, input.capture_height)
        NativeEvidence.parseLayout(input.layout)
        if (input.output_prefix != null) {
            require(input.output_prefix.isNotBlank()) { "output_prefix must not be blank." }
            require(!input.output_prefix.lowercase().endsWith(".png")) {
                "output_prefix is a filename prefix; files get '-native.png' / '-annotated.png' appended."
            }
        }
    }

    fun displayText(text: String, redactSensitive: Boolean): String =
        if (redactSensitive) EvidenceRedaction.redact(text) else text
}
