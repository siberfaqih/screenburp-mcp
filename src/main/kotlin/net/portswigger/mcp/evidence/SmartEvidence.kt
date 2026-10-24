package net.portswigger.mcp.evidence

import kotlinx.serialization.Serializable

@Serializable
data class SelectCriterion(
    val type: String,
    val expression: String,
    val case_sensitive: Boolean = false,
)

/**
 * Input for the `burp_smart_evidence` MCP tool.
 *
 * Either [select] or [goal] (or both) must be provided. Explicit [select]
 * criteria use types `keyword`, `regex`, or `jsonpath`. [goal] is a
 * natural-language description of what the evidence must demonstrate; the
 * engine derives candidate criteria from it and verifies every candidate
 * against the original message text. Only verified exact-text matches are
 * ever captured; anything else is reported explicitly, never invented.
 */
@Serializable
data class BurpSmartEvidence(
    val request_id: String,
    val select: List<SelectCriterion> = emptyList(),
    val goal: String? = null,
    val context_lines: Int = 8,
    val merge_gap_lines: Int = 30,
    val max_regions: Int = 5,
    val layout: String = "side_by_side",
    val capture_width: Int = 1920,
    val capture_height: Int = 1080,
    val highlight_matches: Boolean = true,
    val redact_sensitive: Boolean = true,
    val bounding_boxes: Boolean = true,
    val output_prefix: String? = null,
)

data class ProposedGoalCriteria(
    val criteria: List<MatchCriterion>,
    val notes: List<String>,
)

/**
 * Derives verifiable candidate criteria from a natural-language evidence
 * goal. Heuristics only propose; [EvidenceLocator] verifies. Candidates
 * with no exact-text match are reported as unmatched, never captured.
 */
object GoalCriteria {
    const val MAX_PROPOSED = 10

    private val quoted = Regex("""["'`]([^"'`]{3,200})["'`]""")
    private val url = Regex("""https?://[^\s"'`<>]+""")
    private val fieldMention = Regex(
        """(?i)(?:field|parameter|param|key|attribute|property)\s+[`"']?([A-Za-z][A-Za-z0-9_.-]{1,80})[`"']?"""
    )
    private val identifier = Regex("""[A-Za-z][A-Za-z0-9_]{2,60}""")

    fun propose(goal: String, requestText: String, responseText: String, baseIndex: Int = 0): ProposedGoalCriteria {
        val criteria = mutableListOf<MatchCriterion>()
        val notes = mutableListOf<String>()
        var index = baseIndex
        fun add(type: CriterionType, expression: String, note: String) {
            if (criteria.size >= MAX_PROPOSED) return
            if (criteria.any { it.type == type && it.expression == expression }) return
            criteria += MatchCriterion(index++, type, expression)
            notes += note
        }

        val quotedNames = quoted.findAll(goal).map { it.groupValues[1] }.toSet()
        for (name in quotedNames) {
            add(CriterionType.KEYWORD, name, "quoted phrase from goal")
            if (identifier.matches(name)) {
                add(CriterionType.JSONPATH, "\$..$name", "quoted field '$name' anywhere in JSON")
            }
        }
        for (match in fieldMention.findAll(goal)) {
            val name = match.groupValues[1]
            if (!identifier.matches(name) || name in quotedNames ||
                requestText.contains(name, ignoreCase = true) ||
                responseText.contains(name, ignoreCase = true)
            ) {
                add(CriterionType.KEYWORD, name, "named field from goal")
                if (identifier.matches(name)) {
                    add(CriterionType.JSONPATH, "\$..$name", "field '$name' anywhere in JSON")
                }
            } else {
                notes += "ignoring '$name': looks like prose, not present in messages"
            }
        }
        val urlSources = goal + "\n" + requestText.lineSequence().firstOrNull().orEmpty()
        for (match in url.findAll(urlSources)) {
            val raw = match.value.trimEnd('.', ',', ';', ')')
            val host = raw.substringAfter("://").substringBefore("/").substringBefore("?")
            if (host.isNotEmpty()) add(CriterionType.KEYWORD, host, "URL host from goal/request")
            raw.substringAfter("://").substringAfter("/", "").split("/", "?", "&", "=")
                .map { it.trim() }
                .filter { it.length in 3..80 && identifier.matches(it) }
                .take(5)
                .forEach { add(CriterionType.KEYWORD, it, "URL token from goal/request") }
        }
        if (criteria.isEmpty()) {
            notes += "no concrete phrases, fields, or URLs found in goal; " +
                "falling back to distinctive goal tokens verifiable in the messages"
            goal.split(Regex("""\s+"""))
                .map { it.trim().trim('.', ',', ';', ':', '!', '?', '"', '\'', '`', '(', ')') }
                .filter { it.length >= 6 && identifier.matches(it) }
                .filter { requestText.contains(it, ignoreCase = true) || responseText.contains(it, ignoreCase = true) }
                .distinct()
                .take(MAX_PROPOSED)
                .forEach { add(CriterionType.KEYWORD, it, "distinctive goal token present in messages") }
        }
        return ProposedGoalCriteria(criteria, notes)
    }
}

object SmartEvidence {
    /**
     * Builds red-box [BoxTarget]s for every verified match in [region].
     * Offsets index the original message, so editors holding the raw
     * messages apply directly. Fragments outside 1..500 characters are
     * skipped (mirroring diff-evidence boxing).
     */
    fun regionBoxTargets(region: EvidenceRegion): List<BoxTarget> {
        val side = if (region.side == EvidenceSide.REQUEST) BoxSide.REQUEST else BoxSide.RESPONSE
        return region.matches.mapNotNull { match ->
            val text = match.matchedText
            if (text.length in 1..500) BoxTarget(side, text, match.startOffset, BoundingBox.HIGHLIGHT_LABEL)
            else null
        }
    }

    fun parseCriteria(input: BurpSmartEvidence): List<MatchCriterion> =
        input.select.mapIndexed { i, criterion ->
            val type = when (criterion.type.lowercase()) {
                "keyword" -> CriterionType.KEYWORD
                "regex" -> CriterionType.REGEX
                "jsonpath" -> CriterionType.JSONPATH
                else -> throw IllegalArgumentException(
                    "Select criterion #$i has unsupported type '${criterion.type}'. " +
                        "Supported types: keyword, regex, jsonpath."
                )
            }
            if (criterion.expression.isEmpty()) {
                throw IllegalArgumentException("Select criterion #$i has an empty expression.")
            }
            MatchCriterion(i, type, criterion.expression, criterion.case_sensitive)
        }

    fun validate(input: BurpSmartEvidence) {
        if (input.select.isEmpty() && input.goal.isNullOrBlank()) {
            throw IllegalArgumentException(
                "Provide at least one select criterion or a goal description."
            )
        }
        require(input.context_lines in 0..50) {
            "context_lines must be within 0-50."
        }
        require(input.merge_gap_lines in 0..500) {
            "merge_gap_lines must be within 0-500."
        }
        require(input.max_regions in 1..8) {
            "max_regions must be within 1-8."
        }
        NativeEvidence.requireValidDimensions(input.capture_width, input.capture_height)
        NativeEvidence.parseLayout(input.layout)
        if (input.output_prefix != null) {
            require(input.output_prefix.isNotBlank()) { "output_prefix must not be blank." }
            require(!input.output_prefix.lowercase().endsWith(".png")) {
                "output_prefix is a filename prefix; region files get '-<side>-<n>.png' appended."
            }
        }
    }
}
