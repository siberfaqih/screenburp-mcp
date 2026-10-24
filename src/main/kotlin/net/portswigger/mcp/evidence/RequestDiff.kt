package net.portswigger.mcp.evidence

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

enum class DiffKind { ADDED, REMOVED, CHANGED }

/**
 * One atomic request difference. [location] is a stable pointer such as
 * `query:next`, `header:Authorization`, `cookie:session`, `body:$.role`,
 * `body-form:vin`, or `body-line:12`. Offsets are byte offsets into the
 * respective message ([before] offsets into the baseline, [after] offsets
 * into the test message); -1 when the side has no corresponding text.
 */
data class DiffEntry(
    val kind: DiffKind,
    val location: String,
    val before: String?,
    val after: String?,
    val beforeStart: Int = -1,
    val beforeEnd: Int = -1,
    val afterStart: Int = -1,
    val afterEnd: Int = -1,
    val autoChanged: Boolean = false,
)

data class RequestDiff(
    val entries: List<DiffEntry>,
    val truncated: Boolean,
    val totalChanges: Int,
)

/**
 * Compares a baseline and a modified HTTP request message. Only exact
 * differences are reported; unchanged content is never classified as a
 * modification. Pure string/JSON logic — nothing is sent anywhere.
 */
object RequestDiffer {
    const val MAX_ENTRIES = 100

    fun diff(baseline: String, modified: String): RequestDiff {
        val entries = mutableListOf<DiffEntry>()
        val base = splitMessage(baseline)
        val mod = splitMessage(modified)

        if (base.requestLine != mod.requestLine) {
            entries += diffRequestLine(base, mod)
        }
        entries += diffHeaders(base, mod)
        entries += diffCookies(base, mod)
        entries += diffBodies(base, mod)

        val total = entries.size
        val capped = entries.take(MAX_ENTRIES)
        return RequestDiff(capped, total > MAX_ENTRIES, total)
    }

    private data class MessageParts(
        val text: String,
        val requestLine: String,
        val headers: List<Pair<String, String>>,
        val headerBlockStart: Int,
        val body: String,
        val bodyOffset: Int,
    )

    private fun splitMessage(message: String): MessageParts {
        val normalized = message.replace("\r\n", "\n")
        val lines = normalized.split("\n")
        val requestLine = lines.firstOrNull().orEmpty()
        val blankAt = lines.indexOfFirst { it.isEmpty() }.let { if (it < 0) lines.size else it }
        val headers = lines.drop(1).take(blankAt - 1).mapNotNull { line ->
            val colon = line.indexOf(':')
            if (colon < 0) null else line.substring(0, colon).trim() to line.substring(colon + 1).trim()
        }
        val body = if (blankAt + 1 < lines.size) lines.drop(blankAt + 1).joinToString("\n") else ""
        // Map back to original offsets via search (handles \r\n vs \n).
        val headerBlockStart = message.indexOf("\n").let { if (it < 0) message.length else it + 1 }
        val bodyOffset = if (body.isEmpty()) message.length else message.indexOf(body.take(64)).takeIf { it >= 0 }
            ?: message.length
        return MessageParts(message, requestLine, headers, headerBlockStart, body, bodyOffset)
    }

    private fun diffRequestLine(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        val entries = mutableListOf<DiffEntry>()
        val baseTarget = base.requestLine.substringAfter(' ').substringBeforeLast(' ')
        val modTarget = mod.requestLine.substringAfter(' ').substringBeforeLast(' ')
        val baseMethod = base.requestLine.substringBefore(' ')
        val modMethod = mod.requestLine.substringBefore(' ')
        if (baseMethod != modMethod) {
            entries += DiffEntry(DiffKind.CHANGED, "request-line:method", baseMethod, modMethod)
        }
        val basePath = baseTarget.substringBefore('?')
        val modPath = modTarget.substringBefore('?')
        if (basePath != modPath) {
            entries += DiffEntry(DiffKind.CHANGED, "request-line:path", basePath, modPath)
        }
        entries += diffQuery(
            baseTarget.substringAfter('?', ""), modTarget.substringAfter('?', ""),
            base.text.indexOf(baseTarget).let { if (it < 0) 0 else it + baseTarget.indexOf('?') + 1 },
            mod.text.indexOf(modTarget).let { if (it < 0) 0 else it + modTarget.indexOf('?') + 1 },
        )
        return entries
    }

    private fun parseParams(query: String): List<Pair<String, String>> {
        if (query.isEmpty()) return emptyList()
        return query.split('&').mapNotNull { pair ->
            if (pair.isEmpty()) null
            else {
                val eq = pair.indexOf('=')
                if (eq < 0) pair to "" else pair.substring(0, eq) to pair.substring(eq + 1)
            }
        }
    }

    private fun diffQuery(
        baseQuery: String, modQuery: String, baseOffset: Int, modOffset: Int,
    ): List<DiffEntry> {
        val base = parseParams(baseQuery).associate { it.first to it.second }
        val mod = parseParams(modQuery).associate { it.first to it.second }
        val entries = mutableListOf<DiffEntry>()
        for ((name, value) in base) {
            val other = mod[name]
            when {
                other == null -> entries += DiffEntry(DiffKind.REMOVED, "query:$name", value, null)
                other != value -> {
                    val baseAt = baseQuery.indexOf("$name=$value").let { if (it < 0) -1 else baseOffset + it }
                    val at = modQuery.indexOf("$name=$other").let { if (it < 0) -1 else modOffset + it }
                    entries += DiffEntry(
                        DiffKind.CHANGED, "query:$name", value, other,
                        baseAt, if (baseAt < 0) -1 else baseAt + name.length + 1 + value.length,
                        at, if (at < 0) -1 else at + name.length + 1 + other.length,
                    )
                }
            }
        }
        for ((name, value) in mod) {
            if (name !in base) entries += DiffEntry(DiffKind.ADDED, "query:$name", null, value)
        }
        return entries
    }

    private fun diffHeaders(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        fun multi(parts: MessageParts): Map<String, List<String>> {
            val map = linkedMapOf<String, MutableList<String>>()
            for ((name, value) in parts.headers) {
                map.getOrPut(name.lowercase()) { mutableListOf() } += value
            }
            return map
        }
        val baseMap = multi(base)
        val modMap = multi(mod)
        val entries = mutableListOf<DiffEntry>()
        for ((name, values) in baseMap) {
            val other = modMap[name]
            if (other == null) {
                entries += DiffEntry(DiffKind.REMOVED, "header:$name", values.joinToString(", "), null)
            } else if (other.sorted() != values.sorted()) {
                val valueAt = mod.text.indexOf(other.firstOrNull().orEmpty())
                entries += DiffEntry(
                    DiffKind.CHANGED, "header:$name", values.joinToString(", "), other.joinToString(", "),
                    base.text.indexOf(values.firstOrNull().orEmpty()), -1,
                    valueAt, if (valueAt < 0) -1 else valueAt + other.firstOrNull().orEmpty().length,
                )
            }
        }
        for ((name, values) in modMap) {
            if (name !in baseMap) entries += DiffEntry(DiffKind.ADDED, "header:$name", null, values.joinToString(", "))
        }
        return entries
    }

    private fun parseCookies(headerValue: String): Map<String, String> =
        headerValue.split(';').mapNotNull { part ->
            val trimmed = part.trim()
            if (trimmed.isEmpty()) return@mapNotNull null
            val eq = trimmed.indexOf('=')
            if (eq < 0) trimmed to "" else trimmed.substring(0, eq).trim() to trimmed.substring(eq + 1).trim()
        }.toMap()

    private fun diffCookies(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        val baseCookie = base.headers.firstOrNull { it.first.equals("cookie", ignoreCase = true) }?.second.orEmpty()
        val modCookie = mod.headers.firstOrNull { it.first.equals("cookie", ignoreCase = true) }?.second.orEmpty()
        if (baseCookie == modCookie) return emptyList()
        val baseMap = parseCookies(baseCookie)
        val modMap = parseCookies(modCookie)
        val entries = mutableListOf<DiffEntry>()
        for ((name, value) in baseMap) {
            val other = modMap[name]
            when {
                other == null -> entries += DiffEntry(DiffKind.REMOVED, "cookie:$name", value, null)
                other != value -> entries += DiffEntry(DiffKind.CHANGED, "cookie:$name", value, other)
            }
        }
        for ((name, value) in modMap) {
            if (name !in baseMap) entries += DiffEntry(DiffKind.ADDED, "cookie:$name", null, value)
        }
        return entries
    }

    private fun diffBodies(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        if (base.body == mod.body) return emptyList()
        val baseJson = tryParseJson(base.body)
        val modJson = tryParseJson(mod.body)
        if (baseJson != null && modJson != null) {
            return diffJsonElements(baseJson, modJson, "$", base.body, mod.body, base.bodyOffset, mod.bodyOffset)
        }
        if (looksForm(base.body) && looksForm(mod.body)) {
            return diffFormBodies(base, mod)
        }
        if (base.body.isEmpty()) {
            return listOf(
                DiffEntry(DiffKind.ADDED, "body", null, mod.body.take(2000), -1, -1, mod.bodyOffset, mod.bodyOffset + mod.body.length)
            )
        }
        if (mod.body.isEmpty()) {
            return listOf(DiffEntry(DiffKind.REMOVED, "body", base.body.take(2000), null))
        }
        return diffBodyLines(base, mod)
    }

    private fun tryParseJson(body: String): JsonElement? {
        val trimmed = body.trim()
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return null
        return try {
            Json.parseToJsonElement(trimmed)
        } catch (_: Exception) {
            null
        }
    }

    private fun looksForm(body: String): Boolean =
        body.isNotEmpty() && !body.contains("\n") && body.contains("=") && !body.trimStart().startsWith("{")

    private fun diffFormBodies(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        val baseParams = parseParams(base.body).associate { it.first to it.second }
        val modParams = parseParams(mod.body).associate { it.first to it.second }
        val entries = mutableListOf<DiffEntry>()
        for ((name, value) in baseParams) {
            val other = modParams[name]
            when {
                other == null -> entries += DiffEntry(DiffKind.REMOVED, "body-form:$name", value, null)
                other != value -> {
                    val at = mod.body.indexOf("$name=$other")
                    entries += DiffEntry(
                        DiffKind.CHANGED, "body-form:$name", value, other,
                        base.body.indexOf("$name=$value"), -1,
                        if (at < 0) -1 else mod.bodyOffset + at,
                        if (at < 0) -1 else mod.bodyOffset + at + name.length + 1 + other.length,
                    )
                }
            }
        }
        for ((name, value) in modParams) {
            if (name !in baseParams) entries += DiffEntry(DiffKind.ADDED, "body-form:$name", null, value)
        }
        return entries
    }

    private fun diffJsonElements(
        base: JsonElement, mod: JsonElement, path: String,
        baseBody: String, modBody: String, baseOffset: Int, modOffset: Int,
    ): List<DiffEntry> {
        if (base == mod) return emptyList()
        if (base is JsonObject && mod is JsonObject) {
            val entries = mutableListOf<DiffEntry>()
            for ((key, baseValue) in base) {
                val modValue = mod[key]
                val childPath = "$path.$key"
                if (modValue == null) {
                    entries += DiffEntry(DiffKind.REMOVED, "body:$childPath", baseValue.toString().take(500), null)
                } else {
                    entries += diffJsonElements(baseValue, modValue, childPath, baseBody, modBody, baseOffset, modOffset)
                }
            }
            for ((key, modValue) in mod) {
                if (key !in base) {
                    val at = modBody.indexOf("\"$key\"")
                    entries += DiffEntry(
                        DiffKind.ADDED, "body:$path.$key", null, modValue.toString().take(500),
                        -1, -1,
                        if (at < 0) -1 else modOffset + at,
                        if (at < 0) -1 else modOffset + at + key.length + 2,
                    )
                }
            }
            return entries
        }
        if (base is JsonArray && mod is JsonArray) {
            val entries = mutableListOf<DiffEntry>()
            val common = minOf(base.size, mod.size)
            for (i in 0 until common) {
                entries += diffJsonElements(base[i], mod[i], "$path[$i]", baseBody, modBody, baseOffset, modOffset)
            }
            for (i in common until mod.size) {
                entries += DiffEntry(DiffKind.ADDED, "body:$path[$i]", null, mod[i].toString().take(500))
            }
            for (i in common until base.size) {
                entries += DiffEntry(DiffKind.REMOVED, "body:$path[$i]", base[i].toString().take(500), null)
            }
            return entries
        }
        // Scalar change: locate the new scalar text for highlighting.
        val needle = (mod as? JsonPrimitive)?.let { if (it.isString) it.content else it.toString() } ?: mod.toString()
        val at = if (needle.length in 1..500) modBody.indexOf(needle) else -1
        return listOf(
            DiffEntry(
                DiffKind.CHANGED, "body:$path", base.toString().take(500), mod.toString().take(500),
                -1, -1,
                if (at < 0) -1 else modOffset + at,
                if (at < 0) -1 else modOffset + at + needle.length,
            )
        )
    }

    private fun diffBodyLines(base: MessageParts, mod: MessageParts): List<DiffEntry> {
        val baseLines = base.body.split("\n")
        val modLines = mod.body.split("\n")
        var prefix = 0
        while (prefix < minOf(baseLines.size, modLines.size) && baseLines[prefix] == modLines[prefix]) prefix++
        var suffix = 0
        while (suffix < minOf(baseLines.size, modLines.size) - prefix &&
            baseLines[baseLines.size - 1 - suffix] == modLines[modLines.size - 1 - suffix]
        ) suffix++
        val entries = mutableListOf<DiffEntry>()
        if (prefix + suffix < baseLines.size) {
            entries += DiffEntry(
                DiffKind.REMOVED, "body-lines:${prefix + 1}-${baseLines.size - suffix}",
                baseLines.drop(prefix).dropLast(suffix).joinToString("\n").take(2000), null,
            )
        }
        if (prefix + suffix < modLines.size) {
            val added = modLines.drop(prefix).dropLast(suffix)
            val at = mod.body.indexOf(added.firstOrNull().orEmpty())
            entries += DiffEntry(
                DiffKind.ADDED, "body-lines:${prefix + 1}-${modLines.size - suffix}",
                null, added.joinToString("\n").take(2000),
                -1, -1,
                if (at < 0) -1 else mod.bodyOffset + at, -1,
            )
        }
        return entries.ifEmpty {
            listOf(DiffEntry(DiffKind.CHANGED, "body", base.body.take(500), mod.body.take(500)))
        }
    }
}
