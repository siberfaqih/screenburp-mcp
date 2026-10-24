package net.portswigger.mcp.evidence

import java.net.URLDecoder

enum class ExploitVerdict { SUCCESS, OBSERVED, INCONCLUSIVE, FAILED }
enum class EvidenceKind { PAYLOAD_REFLECTION, OBJECTIVE_MATCH, RESPONSE_DELTA, HINT_MATCH }

data class DetectedPayload(
    val text: String,
    val startOffset: Int,
    val endOffset: Int,
    val location: String,
    val encodings: List<String>,
    val fromHint: Boolean,
    val heuristic: Boolean,
    val confidence: String,
)

data class ResponseEvidence(
    val kind: EvidenceKind,
    val startOffset: Int,
    val endOffset: Int,
    val text: String,
    val lineNumber: Int,
    val detail: String,
)

data class ExploitAnalysis(
    val payload: DetectedPayload,
    val evidence: List<ResponseEvidence>,
    val verdict: ExploitVerdict,
    val confidence: String,
    val rationale: String,
    val volatileExcluded: Int = 0,
)

/**
 * Identifies the submitted payload from a baseline-anchored request diff and
 * locates verified response fragments demonstrating the result. Every
 * fragment is verified by exact substring equality; verdicts are labeled
 * with confidence and never invented.
 */
object PayloadEvidence {
    /**
     * Finds [hint] in [modifiedRequest], tolerating URL-encoding and
     * JSON-escaping while reporting offsets in the original representation.
     */
    fun locateHint(modifiedRequest: String, hint: String, criterionIndex: Int): LocatedMatch {
        require(hint.isNotEmpty()) { "payload_hint must not be empty." }
        val direct = modifiedRequest.indexOf(hint)
        if (direct >= 0) {
            return LocatedMatch(criterionIndex, CriterionType.KEYWORD, hint, direct, direct + hint.length, hint, 1)
        }
        val decodedUrl = runCatching { URLDecoder.decode(hint, "UTF-8") }.getOrNull()
        if (!decodedUrl.isNullOrEmpty() && decodedUrl != hint) {
            val at = modifiedRequest.indexOf(decodedUrl)
            if (at >= 0) {
                return LocatedMatch(criterionIndex, CriterionType.KEYWORD, hint, at, at + decodedUrl.length, decodedUrl, 1)
            }
        }
        val unescaped = hint.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\/", "/")
            .replace("\\n", "\n").replace("\\u003d", "=")
        if (unescaped != hint) {
            val at = modifiedRequest.indexOf(unescaped)
            if (at >= 0) {
                return LocatedMatch(criterionIndex, CriterionType.KEYWORD, hint, at, at + unescaped.length, unescaped, 1)
            }
        }
        throw IllegalArgumentException(
            "payload_hint was not located in the modified request, raw, URL-decoded, " +
                "or JSON-unescaped. Refine the hint; nothing was assumed."
        )
    }

    fun detectPayload(
        modifiedRequest: String,
        diff: RequestDiff,
        payloadHint: String?,
    ): DetectedPayload {
        val scalarChanges = diff.entries.filter {
            it.kind != DiffKind.REMOVED && it.after != null &&
                (it.location.startsWith("query:") || it.location.startsWith("body") ||
                    it.location.startsWith("cookie:") || it.location.startsWith("header:"))
        }
        if (!payloadHint.isNullOrBlank()) {
            val located = try {
                locateHint(modifiedRequest, payloadHint, 0)
            } catch (e: IllegalArgumentException) {
                // The hint may be encoded in the request (e.g. %20 vs +): decode
                // each changed span and compare, keeping original offsets.
                matchHintInChanges(modifiedRequest, scalarChanges, payloadHint) ?: throw e
            }
            val encodings = detectEncodings(payloadHint, located.matchedText)
            val inChange = scalarChanges.any { change ->
                change.afterStart >= 0 && located.startOffset >= change.afterStart &&
                    located.endOffset <= change.afterEnd.let { if (it < 0) Int.MAX_VALUE else it }
            }
            val lineStarts = EvidenceLocator.lineStartOffsets(modifiedRequest)
            val line = lineStarts.binarySearch(located.startOffset).let { if (it < 0) -it - 1 else it + 1 }
            return DetectedPayload(
                text = located.matchedText, startOffset = located.startOffset, endOffset = located.endOffset,
                location = changeLocationAt(scalarChanges, located.startOffset) ?: "request-line-or-body:$line",
                encodings = encodings, fromHint = true, heuristic = false,
                confidence = if (inChange) "high" else "medium",
            )
        }
        val best = scalarChanges
            .filter { it.afterStart >= 0 && it.afterEnd > it.afterStart }
            .maxByOrNull { it.afterEnd - it.afterStart }
            ?: throw IllegalArgumentException(
                "No request modifications with locatable values were detected against " +
                    "the baseline, so no payload can be identified. Supply payload_hint " +
                    "or verify the baseline actually precedes the modification."
            )
        val text = modifiedRequest.substring(best.afterStart, best.afterEnd)
        return DetectedPayload(
            text = text, startOffset = best.afterStart, endOffset = best.afterEnd,
            location = best.location, encodings = detectEncodings(best.after.orEmpty(), text),
            fromHint = false, heuristic = true, confidence = "medium",
        )
    }

    private fun changeLocationAt(changes: List<DiffEntry>, offset: Int): String? =
        changes.firstOrNull { change ->
            if (change.afterStart < 0) return@firstOrNull false
            val end = if (change.afterEnd >= 0) change.afterEnd
            else change.afterStart + (change.after?.length ?: 0)
            offset >= change.afterStart && offset <= end
        }?.location

    private fun matchHintInChanges(
        modifiedRequest: String,
        changes: List<DiffEntry>,
        hint: String,
    ): LocatedMatch? {
        for (change in changes) {
            if (change.afterStart < 0 || change.afterEnd <= change.afterStart) continue
            if (change.afterEnd > modifiedRequest.length) continue
            val span = modifiedRequest.substring(change.afterStart, change.afterEnd)
            val decodedUrl = runCatching { URLDecoder.decode(span, "UTF-8") }.getOrNull()
            val unescaped = span.replace("\\\"", "\"").replace("\\\\", "\\")
            if (decodedUrl == hint || unescaped == hint) {
                return LocatedMatch(0, CriterionType.KEYWORD, hint, change.afterStart, change.afterEnd, span, 1)
            }
        }
        return null
    }

    private fun detectEncodings(hint: String, actual: String): List<String> {
        if (hint == actual) return listOf("raw")
        val encodings = mutableListOf<String>()
        if (runCatching { URLDecoder.decode(actual, "UTF-8") }.getOrNull() == hint) encodings += "url"
        if (actual.replace("\\\"", "\"").replace("\\\\", "\\") == hint) encodings += "json-escape"
        return encodings
    }

    fun analyzeResponse(
        testResponse: String?,
        baselineResponse: String?,
        payload: DetectedPayload,
        objective: String,
        evidenceHint: String?,
        testRequest: String,
    ): ExploitAnalysis {
        require(!objective.isBlank()) { "objective must describe what the evidence should demonstrate." }
        if (testResponse == null) {
            return ExploitAnalysis(
                payload, emptyList(), ExploitVerdict.INCONCLUSIVE, "low",
                "The test pair has no recorded response, so no response evidence can be verified."
            )
        }
        val evidence = mutableListOf<ResponseEvidence>()
        val lineStarts = EvidenceLocator.lineStartOffsets(testResponse)

        // Strategy 1: exact payload reflection (raw + decoded variants).
        val variants = linkedSetOf(payload.text)
        runCatching { URLDecoder.decode(payload.text, "UTF-8") }?.getOrNull()?.let { variants += it }
        for (variant in variants.filter { it.length in 3..2000 }) {
            var from = 0
            while (evidence.size < 10) {
                val at = testResponse.indexOf(variant, from)
                if (at < 0) break
                evidence += ResponseEvidence(
                    EvidenceKind.PAYLOAD_REFLECTION, at, at + variant.length, variant,
                    lineOf(lineStarts, at), "payload occurs verbatim in the test response",
                )
                from = at + maxOf(variant.length, 1)
            }
        }

        // Strategy 2: response delta vs baseline (new segments), excluding
        // volatile per-request headers that can never demonstrate a result.
        val baselineLines = baselineResponse?.split("\n")?.toSet().orEmpty()
        var volatileSkipped = 0
        if (baselineResponse != null) {
            for ((index, line) in testResponse.split("\n").withIndex()) {
                if (line.isBlank() || line in baselineLines) continue
                if (isVolatileHeader(line)) {
                    volatileSkipped++
                    continue
                }
                if (evidence.size >= 20) break
                val at = testResponse.indexOf(line)
                if (at < 0) continue
                evidence += ResponseEvidence(
                    EvidenceKind.RESPONSE_DELTA, at, at + line.length, line.take(500),
                    index + 1, "line present in test response but absent from baseline response",
                )
            }
        }

        // Strategy 3: objective-anchored verified matches (+ optional hint).
        val goal = GoalCriteria.propose(objective, testRequest, testResponse, 1000)
        val criteria = goal.criteria.map { MatchCriterion(it.index, it.type, it.expression, it.caseSensitive) }
            .toMutableList()
        if (!evidenceHint.isNullOrBlank()) {
            criteria += MatchCriterion(2000, CriterionType.KEYWORD, evidenceHint)
        }
        if (criteria.isNotEmpty()) {
            val outcome = EvidenceLocator.locateInMessage(testResponse, criteria)
            for (match in outcome.matches.take(20)) {
                evidence += ResponseEvidence(
                    if (match.criterionIndex == 2000) EvidenceKind.HINT_MATCH else EvidenceKind.OBJECTIVE_MATCH,
                    match.startOffset, match.endOffset, match.matchedText, match.lineNumber,
                    "verified match for '${match.expression}'",
                )
            }
        }

        val reflection = evidence.any { it.kind == EvidenceKind.PAYLOAD_REFLECTION }
        val baselineText = baselineResponse.orEmpty()
        val novelObjective = evidence.any {
            it.kind == EvidenceKind.OBJECTIVE_MATCH && !baselineText.contains(it.text)
        }
        val testStatus = statusClass(testResponse)
        val baseStatus = baselineResponse?.let { statusClass(it) }

        val (verdict, confidence, rationale) = when {
            reflection -> Triple(
                ExploitVerdict.SUCCESS, "high",
                "Payload occurs verbatim in the test response."
            )
            novelObjective -> Triple(
                ExploitVerdict.SUCCESS, "medium",
                "Objective-anchored fragment verified in the test response and absent from the baseline response."
            )
            testStatus in listOf(4, 5) && baseStatus in listOf(2, 3) -> Triple(
                ExploitVerdict.FAILED, "medium",
                "Test response status ${testStatus}xx vs baseline ${baseStatus}xx with no reflection or novel objective fragment."
            )
            evidence.any { it.kind == EvidenceKind.RESPONSE_DELTA } -> Triple(
                ExploitVerdict.OBSERVED, "medium",
                "Test response differs from baseline but no direct payload link was verified."
            )
            else -> Triple(
                ExploitVerdict.INCONCLUSIVE, "low",
                "No verified fragment links the payload to an observable effect."
            )
        }
        return ExploitAnalysis(payload, evidence.take(20), verdict, confidence, rationale, volatileSkipped)
    }

    /** Per-request headers that change on every response and prove nothing. */
    fun isVolatileHeader(line: String): Boolean {
        val name = line.substringBefore(':').trim().lowercase()
        return name in setOf("date", "content-length", "etag", "last-modified", "age", "expires", "set-cookie", "x-response-time", "x-request-id")
    }

    private fun statusClass(response: String): Int? =
        response.lineSequence().firstOrNull()?.let { Regex("""HTTP/\S+\s+(\d{3})""").find(it) }
            ?.groupValues?.get(1)?.firstOrNull()?.digitToIntOrNull()

    private fun lineOf(lineStarts: List<Int>, offset: Int): Int {
        val line = lineStarts.binarySearch(offset.coerceAtLeast(0))
        return ((if (line < 0) -line - 2 else line).coerceAtLeast(0)) + 1
    }
}
