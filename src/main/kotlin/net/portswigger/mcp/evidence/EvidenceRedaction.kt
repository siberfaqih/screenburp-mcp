package net.portswigger.mcp.evidence

/**
 * Shared sensitive-data redaction for evidence rendering.
 *
 * Applied to a *derivative* of the original HTTP message. The original
 * bytes captured by Burp are never mutated; callers must clearly label
 * redacted output as a derivative in their MCP text summary.
 */
object EvidenceRedaction {
    private val sensitiveHeader = Regex(
        "(?im)^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token):[^\\n]*$"
    )
    private val sensitiveJson = Regex(
        "(?i)(\\\"(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|password|passwd|secret|api[_-]?key)\\\"\\s*:\\s*\\\")[^\\\"]*(\\\")"
    )
    private val sensitiveQuery = Regex(
        "(?i)([?&](?:access[_-]?token|refresh[_-]?token|token|password|secret|api[_-]?key)=)[^&\\s]+"
    )
    private val jwt = Regex("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")

    fun redact(message: String): String = message
        .replace(sensitiveHeader) { "${it.groupValues[1]}: [REDACTED]" }
        .replace(sensitiveJson) { "${it.groupValues[1]}[REDACTED]${it.groupValues[2]}" }
        .replace(sensitiveQuery) { "${it.groupValues[1]}[REDACTED]" }
        .replace(jwt, "[REDACTED JWT]")

    /**
     * Byte ranges of secret values in the ORIGINAL message, for pixel
     * redaction overlays. Header names and JSON keys are excluded so only
     * the secret itself is blacked out.
     */
    fun secretSpans(message: String): List<IntRange> {
        val spans = mutableListOf<IntRange>()
        for (match in sensitiveHeader.findAll(message)) {
            val line = match.value
            val colon = line.indexOf(':')
            if (colon >= 0 && colon + 1 < line.length) {
                var start = match.range.first + colon + 1
                while (start <= match.range.last && message[start].isWhitespace()) start++
                if (start <= match.range.last) spans += start..match.range.last
            }
        }
        for (match in sensitiveJson.findAll(message)) {
            val full = match.value
            val keyEnd = match.groups[1]?.value?.length ?: continue
            val secretStart = match.range.first + keyEnd
            val secretEnd = match.range.last - 1
            if (secretStart <= secretEnd) spans += secretStart..secretEnd
        }
        for (match in sensitiveQuery.findAll(message)) {
            val prefix = match.groups[1]?.value?.length ?: continue
            val secretStart = match.range.first + prefix
            if (secretStart <= match.range.last) spans += secretStart..match.range.last
        }
        for (match in jwt.findAll(message)) {
            if (!match.range.isEmpty()) spans += match.range.first..match.range.last
        }
        return mergeRanges(spans.filter { !it.isEmpty() })
    }

    private fun mergeRanges(ranges: List<IntRange>): List<IntRange> {
        val sorted = ranges.sortedBy { it.first }
        val merged = mutableListOf<IntRange>()
        for (range in sorted) {
            val last = merged.lastOrNull()
            if (last != null && range.first <= last.last + 1) {
                merged[merged.size - 1] = last.first..maxOf(last.last, range.last)
            } else {
                merged += range
            }
        }
        return merged
    }

    fun looksRedacted(message: String): Boolean =
        message.contains("[REDACTED]") || message.contains("[REDACTED JWT]")
}
