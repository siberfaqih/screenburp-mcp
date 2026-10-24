package net.portswigger.mcp.evidence

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * Minimal JSONPath evaluator over [JsonElement].
 *
 * Supported subset (anything else returns an explicit error, never a guess):
 * `$`, `.name`, `['name']`, `["name"]`, `[N]` (array index, negative counts
 * from the end), `[*]` / `.*` (all children/elements), `..name`
 * (recursive descent). Filters (`[?(...)]`), slices, and scripts are not
 * supported.
 */
object JsonPath {
    data class MatchedNode(val element: JsonElement, val path: String)

    fun evaluate(root: JsonElement, path: String): List<MatchedNode> {
        val tokens = tokenize(path)
        var current = listOf(MatchedNode(root, "$"))
        for (token in tokens) {
            current = current.flatMap { applyToken(it, token) }
        }
        return current
    }

    private sealed interface Token {
        data class Child(val name: String) : Token
        data class Index(val index: Int) : Token
        data object Wildcard : Token
        data class Descent(val name: String) : Token
    }

    private fun tokenize(path: String): List<Token> {
        val trimmed = path.trim()
        require(trimmed.startsWith("$")) { "JSONPath must start with '\$': $path" }
        val tokens = mutableListOf<Token>()
        var i = 1
        while (i < trimmed.length) {
            when {
                trimmed.startsWith("..", i) -> {
                    i += 2
                    if (trimmed.startsWith("*", i)) {
                        i++
                        tokens += Token.Descent("*")
                    } else {
                        val name = readName(trimmed, i, "after '..'")
                        i = name.second
                        tokens += Token.Descent(name.first)
                    }
                }
                trimmed[i] == '.' -> {
                    i++
                    if (trimmed.startsWith("*", i)) {
                        i++
                        tokens += Token.Wildcard
                    } else {
                        val name = readName(trimmed, i, "after '.'")
                        i = name.second
                        tokens += Token.Child(name.first)
                    }
                }
                trimmed[i] == '[' -> {
                    val close = trimmed.indexOf(']', i)
                    require(close > i) { "Unclosed '[' in JSONPath: $path" }
                    val inner = trimmed.substring(i + 1, close).trim()
                    when {
                        inner == "*" -> tokens += Token.Wildcard
                        inner.startsWith("'") || inner.startsWith("\"") -> {
                            require(inner.length >= 2 && inner.endsWith(inner[0].toString())) {
                                "Mismatched quotes in JSONPath: $path"
                            }
                            tokens += Token.Child(inner.substring(1, inner.length - 1))
                        }
                        inner.toIntOrNull() != null -> tokens += Token.Index(inner.toInt())
                        else -> throw IllegalArgumentException(
                            "Unsupported JSONPath bracket '$inner' in: $path. " +
                                "Supported: ['name'], [N], [*]."
                        )
                    }
                    i = close + 1
                }
                trimmed[i].isWhitespace() -> i++
                else -> throw IllegalArgumentException(
                    "Unexpected character '${trimmed[i]}' in JSONPath: $path"
                )
            }
        }
        return tokens
    }

    private fun readName(path: String, from: Int, context: String): Pair<String, Int> {
        require(from < path.length) { "Missing name $context in JSONPath: $path" }
        if (path[from] == '*' && (from + 1 >= path.length || path[from + 1] == '.' || path[from + 1] == '[')) {
            return "*" to from + 1
        }
        var i = from
        while (i < path.length && (path[i].isLetterOrDigit() || path[i] == '_' || path[i] == '-' || path[i] == '$')) i++
        require(i > from) { "Missing name $context in JSONPath: $path" }
        return path.substring(from, i) to i
    }

    private fun applyToken(node: MatchedNode, token: Token): List<MatchedNode> = when (token) {
        is Token.Child -> {
            val obj = node.element as? JsonObject ?: return emptyList()
            val child = obj[token.name] ?: return emptyList()
            listOf(MatchedNode(child, "${node.path}.${token.name}"))
        }
        is Token.Index -> {
            val arr = node.element as? JsonArray ?: return emptyList()
            val idx = if (token.index < 0) arr.size + token.index else token.index
            if (idx !in 0 until arr.size) return emptyList()
            listOf(MatchedNode(arr[idx], "${node.path}[$idx]"))
        }
        Token.Wildcard -> when (val el = node.element) {
            is JsonObject -> el.entries.map { MatchedNode(it.value, "${node.path}.${it.key}") }
            is JsonArray -> el.mapIndexed { idx, child -> MatchedNode(child, "${node.path}[$idx]") }
            else -> emptyList()
        }
        is Token.Descent -> {
            val found = mutableListOf<MatchedNode>()
            fun visit(current: MatchedNode) {
                when (val el = current.element) {
                    is JsonObject -> {
                        for ((key, child) in el.entries) {
                            val childNode = MatchedNode(child, "${current.path}.$key")
                            if (token.name == "*" || key == token.name) found += childNode
                            visit(childNode)
                        }
                    }
                    is JsonArray -> el.forEachIndexed { idx, child -> visit(MatchedNode(child, "${current.path}[$idx]")) }
                    else -> Unit
                }
            }
            visit(node)
            found
        }
    }
}
