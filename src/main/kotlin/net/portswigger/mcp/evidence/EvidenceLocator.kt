package net.portswigger.mcp.evidence

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive

enum class CriterionType { KEYWORD, REGEX, JSONPATH }
enum class EvidenceSide { REQUEST, RESPONSE }

data class MatchCriterion(
    val index: Int,
    val type: CriterionType,
    val expression: String,
    val caseSensitive: Boolean = false,
)

data class LocatedMatch(
    val criterionIndex: Int,
    val type: CriterionType,
    val expression: String,
    val startOffset: Int,
    val endOffset: Int,
    val matchedText: String,
    val lineNumber: Int,
    val nodePath: String? = null,
)

data class EvidenceRegion(
    val side: EvidenceSide,
    val startLine: Int,
    val endLine: Int,
    val startOffset: Int,
    val endOffset: Int,
    val matches: List<LocatedMatch>,
)

data class LocateOutcome(
    val matches: List<LocatedMatch>,
    val unverified: List<String>,
    val cappedCriteria: List<Int>,
    val skipped: List<String>,
)

/**
 * Content-aware evidence location over the *original* HTTP message text.
 * The message is never modified; every returned match is verified by exact
 * substring equality at its offsets.
 */
object EvidenceLocator {
    const val MAX_MATCHES_PER_CRITERION = 50

    fun locateInMessage(message: String, criteria: List<MatchCriterion>): LocateOutcome {
        val lineStarts = lineStartOffsets(message)
        val matches = mutableListOf<LocatedMatch>()
        val unverified = mutableListOf<String>()
        val capped = mutableListOf<Int>()
        val skipped = mutableListOf<String>()
        for (criterion in criteria) {
            val found = when (criterion.type) {
                CriterionType.KEYWORD -> locateKeyword(message, criterion, lineStarts)
                CriterionType.REGEX -> locateRegex(message, criterion, lineStarts)
                CriterionType.JSONPATH -> locateJsonPath(message, criterion, lineStarts, unverified, skipped)
            }
            if (found.size >= MAX_MATCHES_PER_CRITERION) capped += criterion.index
            matches += found.take(MAX_MATCHES_PER_CRITERION)
        }
        matches.sortWith(compareBy({ it.startOffset }, { it.endOffset }))
        return LocateOutcome(matches, unverified, capped, skipped)
    }

    fun groupIntoRegions(
        side: EvidenceSide,
        message: String,
        matches: List<LocatedMatch>,
        contextLines: Int,
        mergeGapLines: Int,
    ): List<EvidenceRegion> {
        if (matches.isEmpty()) return emptyList()
        val lineStarts = lineStartOffsets(message)
        val totalLines = lineStarts.size
        data class Span(var startLine: Int, var endLine: Int, val bucket: MutableList<LocatedMatch>)
        val spans = mutableListOf<Span>()
        for (match in matches) {
            val startLine = (match.lineNumber - contextLines).coerceAtLeast(1)
            val endLine = (lineNumberOfOffset(lineStarts, match.endOffset - 1) + contextLines).coerceAtMost(totalLines)
            val last = spans.lastOrNull()
            if (last != null && startLine - last.endLine <= mergeGapLines) {
                last.endLine = maxOf(last.endLine, endLine)
                last.bucket += match
            } else {
                spans += Span(startLine, endLine, mutableListOf(match))
            }
        }
        return spans.map { span ->
            EvidenceRegion(
                side = side,
                startLine = span.startLine,
                endLine = span.endLine,
                startOffset = lineStarts[span.startLine - 1],
                endOffset = lineEndOffset(message, lineStarts, span.endLine),
                matches = span.bucket.sortedWith(compareBy({ it.startOffset }, { it.endOffset })),
            )
        }
    }

    fun lineStartOffsets(message: String): List<Int> {
        val starts = mutableListOf(0)
        message.forEachIndexed { index, char -> if (char == '\n') starts += index + 1 }
        return starts
    }

    private fun lineNumberOfOffset(lineStarts: List<Int>, offset: Int): Int {
        var line = lineStarts.binarySearch(offset.coerceAtLeast(0))
        if (line < 0) line = -line - 2
        return (line.coerceAtLeast(0)) + 1
    }

    private fun lineEndOffset(message: String, lineStarts: List<Int>, lineNumber: Int): Int {
        val nextStart = if (lineNumber < lineStarts.size) lineStarts[lineNumber] else message.length + 1
        return (nextStart - 1).coerceAtMost(message.length)
    }

    private fun locateKeyword(
        message: String,
        criterion: MatchCriterion,
        lineStarts: List<Int>,
    ): List<LocatedMatch> {
        require(criterion.expression.isNotEmpty()) { "Criterion #${criterion.index} has an empty expression." }
        val needle = criterion.expression
        val found = mutableListOf<LocatedMatch>()
        var from = 0
        while (from <= message.length - needle.length && found.size < MAX_MATCHES_PER_CRITERION) {
            val at = message.indexOf(needle, from, ignoreCase = !criterion.caseSensitive)
            if (at < 0) break
            val text = message.substring(at, at + needle.length)
            found += LocatedMatch(
                criterion.index, criterion.type, criterion.expression,
                at, at + needle.length, text, lineNumberOfOffset(lineStarts, at),
            )
            from = at + maxOf(needle.length, 1)
        }
        return found
    }

    private fun locateRegex(
        message: String,
        criterion: MatchCriterion,
        lineStarts: List<Int>,
    ): List<LocatedMatch> {
        val pattern = try {
            val options = if (criterion.caseSensitive) emptySet() else setOf(RegexOption.IGNORE_CASE)
            Regex(criterion.expression, options)
        } catch (e: Exception) {
            throw IllegalArgumentException(
                "Criterion #${criterion.index} has an invalid regular expression " +
                    "'${criterion.expression}': ${e.message}"
            )
        }
        return pattern.findAll(message)
            .take(MAX_MATCHES_PER_CRITERION)
            .filter { it.range.first <= it.range.last }
            .map { match ->
                LocatedMatch(
                    criterion.index, criterion.type, criterion.expression,
                    match.range.first, match.range.last + 1, match.value,
                    lineNumberOfOffset(lineStarts, match.range.first),
                )
            }.toList()
    }

    private fun locateJsonPath(
        message: String,
        criterion: MatchCriterion,
        lineStarts: List<Int>,
        unverified: MutableList<String>,
        skipped: MutableList<String>,
    ): List<LocatedMatch> {
        val bodyOffset = message.indexOf("\n\n").let { if (it < 0) 0 else it + 2 }
        val body = message.substring(bodyOffset)
        val root: JsonElement = try {
            Json.parseToJsonElement(body)
        } catch (e: Exception) {
            // Not an error by itself: the other side of the pair may be JSON.
            // Callers report this explicitly and only fail when nothing
            // matched anywhere.
            skipped += "criterion #${criterion.index} (jsonpath '${criterion.expression}') " +
                "skipped here: body is not JSON (${e.message?.take(120)})"
            return emptyList()
        }
        val nodes = try {
            JsonPath.evaluate(root, criterion.expression)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Criterion #${criterion.index} (jsonpath): ${e.message}")
        }
        val found = mutableListOf<LocatedMatch>()
        for (node in nodes) {
            if (found.size >= MAX_MATCHES_PER_CRITERION) break
            val (searchText, label) = nodeSearchText(node)
            val at = body.indexOf(searchText)
            if (at < 0) {
                unverified += "jsonpath '${criterion.expression}' -> ${node.path}: " +
                    "$label text not found verbatim in the body (encoding escapes?)"
                continue
            }
            val start = bodyOffset + at
            val text = message.substring(start, start + searchText.length)
            found += LocatedMatch(
                criterion.index, criterion.type, criterion.expression,
                start, start + searchText.length, text,
                lineNumberOfOffset(lineStarts, start), node.path,
            )
        }
        return found
    }

    private fun nodeSearchText(node: JsonPath.MatchedNode): Pair<String, String> {
        val element = node.element
        if (element is JsonPrimitive) {
            if (element.isString) return element.content to "value"
            return element.jsonPrimitive.toString() to "value"
        }
        val key = node.path.substringAfterLast('.').substringAfterLast('[').trimEnd(']')
        if (key.isNotEmpty() && key != node.path) return "\"$key\"" to "key"
        val serialized = Json.encodeToString(JsonElement.serializer(), element)
        return serialized to "node"
    }
}
