package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.types.ContentBlock
import io.modelcontextprotocol.kotlin.sdk.types.ImageContent
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.evidence.BurpCaptureEvidence
import net.portswigger.mcp.evidence.BoundingBox
import net.portswigger.mcp.evidence.BoxSide
import net.portswigger.mcp.evidence.BoxTarget
import net.portswigger.mcp.evidence.BurpDiffEvidence
import net.portswigger.mcp.evidence.BurpSmartEvidence
import net.portswigger.mcp.evidence.CaretPlacement
import net.portswigger.mcp.evidence.DiffEvidence
import net.portswigger.mcp.evidence.DiffKind
import net.portswigger.mcp.evidence.EvidenceAnnotation
import net.portswigger.mcp.evidence.EvidenceHighlight
import net.portswigger.mcp.evidence.EvidenceKind
import net.portswigger.mcp.evidence.EvidenceLocator
import net.portswigger.mcp.evidence.EvidenceOverlay
import net.portswigger.mcp.evidence.EvidenceRedaction
import net.portswigger.mcp.evidence.EvidenceRegion
import net.portswigger.mcp.evidence.EvidenceRenderer
import net.portswigger.mcp.evidence.EvidenceSide
import net.portswigger.mcp.evidence.GoalCriteria
import net.portswigger.mcp.evidence.LocatedMatch
import net.portswigger.mcp.evidence.MatchCriterion
import net.portswigger.mcp.evidence.NativeCaptureResult
import net.portswigger.mcp.evidence.NativeEditorCapture
import net.portswigger.mcp.evidence.NativeEvidence
import net.portswigger.mcp.evidence.PayloadEvidence
import net.portswigger.mcp.evidence.PlacedBox
import net.portswigger.mcp.evidence.RepeaterCapture
import net.portswigger.mcp.evidence.ExploitAnalysis
import net.portswigger.mcp.evidence.RequestDiff
import net.portswigger.mcp.evidence.RequestDiffer
import net.portswigger.mcp.evidence.SmartEvidence
import net.portswigger.mcp.schema.encodeHistoryItem
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.DataAccessSecurity
import net.portswigger.mcp.security.DataAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import net.portswigger.mcp.security.filterConfigCredentials
import java.awt.KeyboardFocusManager
import java.io.File
import java.util.Base64
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkDataAccessOrDeny(
    accessType: DataAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = DataAccessSecurity.checkDataAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun buildHttp2HeaderList(
    pseudoHeaders: Map<String, String>, headers: Map<String, String>
): List<HttpHeader> {
    val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

    val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
        orderedPseudoHeaderNames.forEach { name ->
            val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
            if (value != null) {
                put(name, value)
            }
        }

        pseudoHeaders.forEach { (key, value) ->
            val properKey = if (key.startsWith(":")) key else ":$key"
            if (!containsKey(properKey)) {
                put(properKey, value)
            }
        }
    }

    return (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
}

/**
 * Normalizes HTTP request line endings from MCP clients.
 *
 * MCP clients (e.g. Claude Code) often emit `\r\n` as the 4-character literal
 * sequence backslash-r-backslash-n in JSON tool parameters rather than actual
 * CR (0x0D) + LF (0x0A) bytes. The resulting text parses as a single line,
 * which strict servers (e.g. Apache-Coyote) reject with 400 Bad Request and
 * which Burp/Montoya may "repair" by injecting headers after the body
 * separator.
 *
 * Normalization is applied only to the request prelude (request line and
 * headers, up to and including the first blank line). The body is preserved
 * verbatim so that legitimate escape sequences in bodies — e.g. `\n` inside a
 * JSON string literal — and binary payloads remain byte-exact. If no blank
 * line is present, the entire content is treated as prelude.
 */
internal fun normalizeHttpContent(content: String): String {
    val preludeEnd = findPreludeEnd(content) ?: return normalizePrelude(content)
    return normalizePrelude(content.substring(0, preludeEnd)) + content.substring(preludeEnd)
}

private val BLANK_LINE_MARKERS = listOf(
    "\r\n\r\n",         // actual CRLF blank line
    "\n\n",              // actual LF blank line
    "\\r\\n\\r\\n",     // literal CRLF blank line
    "\\n\\n",            // literal LF blank line
)

private fun findPreludeEnd(content: String): Int? {
    var bestStart = -1
    var bestLen = 0
    for (marker in BLANK_LINE_MARKERS) {
        val idx = content.indexOf(marker)
        if (idx >= 0 && (bestStart < 0 || idx < bestStart)) {
            bestStart = idx
            bestLen = marker.length
        }
    }
    return if (bestStart < 0) null else bestStart + bestLen
}

private fun normalizePrelude(prelude: String): String = prelude
    .replace("\\r\\n", "\n")   // Literal \r\n escape sequences → LF
    .replace("\\n", "\n")      // Remaining literal \n → LF
    .replace("\\r", "")        // Remaining literal \r → remove
    .replace("\r", "")          // Actual CR → remove
    .replace("\n", "\r\n")      // All LF → proper CRLF

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = normalizeHttpContent(content)

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        currentCoroutineContext().ensureActive()
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpUnitTool<CreateRepeaterTab>("Creates an HTTP/1.1 Repeater tab with the specified raw HTTP request and optional tab name. Make sure to use carriage returns appropriately. Prefer create_repeater_tab_http2 for modern web targets that speak HTTP/2.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<CreateRepeaterTabHttp2>("Creates an HTTP/2 Repeater tab with the specified HTTP/2 request and optional tab name. Use this by default for modern web targets. Do NOT pass headers to the body parameter.") {
        val headerList = buildHttp2HeaderList(pseudoHeaders, headers)
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpUnitTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val fixedContent = normalizeHttpContent(content)
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportProjectOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        val json = api.burpSuite().exportUserOptionsAsJson()
        if (config.filterConfigCredentials) {
            filterConfigCredentials(json)
        } else {
            json
        }
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Inject this payload into requests to detect server-side interactions (DNS lookups, HTTP requests, SMTP). " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")

            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }

            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload. " +
            "Returns interaction details including type, timestamp, client IP, and protocol-specific data."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")

            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }

            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") {
                    Json.encodeToString(it.toSerializableForm())
                }
            }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<ScreenshotProxyHttpHistory>(
        "Renders one Burp Proxy HTTP history request and response as a headless PNG and returns it as MCP image content. " +
            "Supports text highlights and numbered annotation callouts. Use get_proxy_http_history to identify the " +
            "zero-based offset. Secrets are redacted by default."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history screenshot")
        }
        if (!allowed) {
            return@mcpTool listOf(TextContent("HTTP history access denied by Burp Suite"))
        }
        require(offset >= 0) { "offset must be zero or greater" }

        val item = api.proxy().history().asSequence().drop(offset).firstOrNull()
            ?: return@mcpTool listOf(TextContent("No proxy HTTP history item exists at offset $offset"))
        renderEvidence(
            request = item.request().toString(),
            response = item.response()?.toString(),
            title = title,
            redactSecrets = redactSecrets,
            maxBodyCharacters = maxBodyCharacters,
            highlights = highlights,
            annotations = annotations,
            source = "proxy HTTP history offset $offset",
        )
    }

    mcpTool<ScreenshotProxyHttpHistoryRegex>(
        "Finds a Burp Proxy HTTP history item by regular expression, renders its request and response headlessly, " +
            "and returns a PNG as MCP image content with optional text highlights and numbered annotation callouts. " +
            "matchOffset is zero-based among matching items."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history screenshot")
        }
        if (!allowed) {
            return@mcpTool listOf(TextContent("HTTP history access denied by Burp Suite"))
        }
        require(matchOffset >= 0) { "matchOffset must be zero or greater" }

        val compiledRegex = Pattern.compile(regex)
        val item = api.proxy().history { it.contains(compiledRegex) }.asSequence().drop(matchOffset).firstOrNull()
            ?: return@mcpTool listOf(TextContent("No proxy HTTP history item matched regex at matchOffset $matchOffset"))
        renderEvidence(
            request = item.request().toString(),
            response = item.response()?.toString(),
            title = title,
            redactSecrets = redactSecrets,
            maxBodyCharacters = maxBodyCharacters,
            highlights = highlights,
            annotations = annotations,
            source = "proxy HTTP history regex match $matchOffset",
        )
    }

    mcpTool<BurpCaptureEvidence>(
        "Captures a native Burp Suite evidence PNG from an actual Proxy history " +
            "request-response pair selected by request_id (zero-based Proxy history " +
            "offset, e.g. \"123\"). Mode native_editor renders Burp's real HTTP " +
            "message editors via the Montoya API and captures their Swing pixels; " +
            "mode repeater captures the actual on-screen Repeater pixels with the " +
            "platform screen-capture facility. Highlighting uses the native editor " +
            "search expression (first term per side) plus verified red boxes " +
            "(3px #FF0000, sharp, transparent) around every highlight-term " +
            "occurrence when bounding_boxes is true. The PNG shows the visible " +
            "viewport only. Unsupported capabilities produce explicit errors, never " +
            "simulated screenshots."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history evidence capture")
        }
        if (!allowed) {
            return@mcpTool listOf(TextContent("HTTP history access denied by Burp Suite"))
        }
        val captureMode = NativeEvidence.parseMode(mode)
        val captureLayout = NativeEvidence.parseLayout(layout)
        NativeEvidence.requireInheritedTheme(theme)
        NativeEvidence.requireValidDimensions(capture_width, capture_height)
        NativeEvidence.requirePngOutput(output)

        val item = NativeEvidence.resolveProxyItem(api, request_id)

        when (captureMode) {
            net.portswigger.mcp.evidence.CaptureMode.NATIVE_EDITOR -> {
                // Raw Burp objects only: editors never receive rebuilt messages.
                val originalRequest = item.request()
                val originalResponse = item.response()
                val requestText = originalRequest.toString()
                val responseText = originalResponse?.toString()
                val requestSearch = NativeEvidence.firstSearchTerm(highlight.request)
                    ?.takeIf { !redact_sensitive || EvidenceRedaction.redact(it) == it }
                val responseSearch = NativeEvidence.firstSearchTerm(highlight.response)
                    ?.takeIf { !redact_sensitive || EvidenceRedaction.redact(it) == it }
                val redactTargets = if (redact_sensitive) {
                    secretBoxTargets(requestText, BoxSide.REQUEST) +
                        (responseText?.let { secretBoxTargets(it, BoxSide.RESPONSE) }.orEmpty())
                } else emptyList()
                val outlineTargets = if (bounding_boxes) {
                    NativeEvidence.highlightBoxTargets(requestText, highlight.request, BoxSide.REQUEST, redact_sensitive) +
                        (responseText?.let {
                            NativeEvidence.highlightBoxTargets(it, highlight.response, BoxSide.RESPONSE, redact_sensitive)
                        }.orEmpty())
                } else emptyList()
                val result = NativeEditorCapture.capture(
                    api, originalRequest, originalResponse,
                    capture_width, capture_height, captureLayout,
                    requestSearch, responseSearch, boxTargets = outlineTargets + redactTargets,
                ).copy(redacted = redact_sensitive)
                val redactedBase = applyRedactionOverlay(result.png, result.placedBoxes)
                val outlineBoxes = result.placedBoxes.filter { it.label != BoundingBox.REDACTED_LABEL }
                val finalPng = if (bounding_boxes && outlineBoxes.isNotEmpty()) {
                    BoundingBox.drawBoxes(redactedBase, outlineBoxes)
                } else redactedBase
                val savedPath = output?.let { writeEvidenceFile(it, finalPng, api) }
                renderNativeEvidence(
                    result, finalPng,
                    "proxy HTTP history offset ${request_id.trim().removePrefix("proxy:")}", savedPath,
                    boundingBoxes = bounding_boxes,
                )
            }

            net.portswigger.mcp.evidence.CaptureMode.REPEATER -> {
                val regionValues = listOf(region_x, region_y, region_width, region_height)
                if (regionValues.any { it != null } && regionValues.any { it == null }) {
                    throw IllegalArgumentException(
                        "Pass all of region_x/region_y/region_width/region_height, or none " +
                            "to capture the Burp suite frame."
                    )
                }
                val image = if (regionValues.all { it != null }) {
                    RepeaterCapture.captureRectangle(
                        region_x!!, region_y!!, region_width!!, region_height!!
                    )
                } else {
                    RepeaterCapture.captureSuiteFrame(api.userInterface().swingUtils().suiteFrame())
                }
                val png = NativeEditorCapture.encodePng(image)
                val savedPath = output?.let { writeEvidenceFile(it, png, api) }
                val summary = buildString {
                    append("Captured actual on-screen Burp pixels (repeater mode) at ")
                    append("${image.width}x${image.height} from proxy HTTP history request_id $request_id. ")
                    append("Ensure the intended Repeater tab was in the foreground; selection, ")
                    append("highlighting, and scroll positions are preserved exactly as visible. ")
                    append("Montoya exposes no Repeater tab enumeration, so the tab cannot be ")
                    append("selected programmatically. ")
                    if (redact_sensitive) append("Note: pixel redaction is not applied in repeater mode; ")
                    append("Verify no secrets are visible before sharing. ")
                    if (savedPath != null) append("Saved to $savedPath.")
                }
                listOf(
                    TextContent(summary),
                    ImageContent(data = Base64.getEncoder().encodeToString(png), mimeType = "image/png"),
                )
            }
        }
    }

    mcpTool<BurpSmartEvidence>(
        "Content-aware native evidence capture for long HTTP messages. Locates " +
            "keyword, regex, or JSONPath matches in the original Proxy history " +
            "message (selected by request_id), scrolls Burp's real HTTP editors " +
            "to each distant region via verified caret placement, and captures " +
            "the native Swing pixels per region with verified red boxes " +
            "(3px #FF0000, sharp, transparent) around the region matches when " +
            "bounding_boxes is true. The complete original request " +
            "and response are always returned as separate text artifacts. " +
            "Alternatively describe the goal in natural language and candidate " +
            "criteria are derived and verified automatically. Only verified " +
            "exact-text matches are captured; anything else is reported " +
            "explicitly, never invented."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history smart capture")
        }
        if (!allowed) {
            return@mcpTool listOf(TextContent("HTTP history access denied by Burp Suite"))
        }
        SmartEvidence.validate(this)
        val item = NativeEvidence.resolveProxyItem(api, request_id)
        val requestText = item.request().toString()
        val responseText = item.response()?.toString()

        var criteria = SmartEvidence.parseCriteria(this)
        val goalNotes = mutableListOf<String>()
        if (!goal.isNullOrBlank()) {
            val proposed = GoalCriteria.propose(goal, requestText, responseText.orEmpty(), criteria.size)
            criteria = criteria + proposed.criteria
            goalNotes += proposed.notes
        }
        if (criteria.isEmpty()) {
            throw IllegalArgumentException(
                "Goal produced no verifiable criteria (notes: ${goalNotes.joinToString("; ")}). " +
                    "Provide explicit select criteria with keyword, regex, or jsonpath types."
            )
        }

        val layout = NativeEvidence.parseLayout(this.layout)
        val requestOutcome = EvidenceLocator.locateInMessage(requestText, criteria)
        val responseOutcome = responseText?.let { EvidenceLocator.locateInMessage(it, criteria) }
        val requestRegions = EvidenceLocator.groupIntoRegions(
            EvidenceSide.REQUEST, requestText, requestOutcome.matches, context_lines, merge_gap_lines
        )
        val responseRegions = if (responseText != null && responseOutcome != null) {
            EvidenceLocator.groupIntoRegions(
                EvidenceSide.RESPONSE, responseText, responseOutcome.matches, context_lines, merge_gap_lines
            )
        } else emptyList()
        // Response evidence first: findings usually live in the response.
        val allRegions = responseRegions + requestRegions
        val matchedCriterionIndices =
            (requestOutcome.matches + (responseOutcome?.matches.orEmpty())).map { it.criterionIndex }.toSet()
        val skippedNotes = requestOutcome.skipped.map { "request: $it" } +
            (responseOutcome?.skipped.orEmpty().map { "response: $it" })
        val unmatched = criteria
            .filter { it.index !in matchedCriterionIndices }
            .map { "#${it.index} ${it.type.name.lowercase()} '${it.expression}'" }
        if (allRegions.isEmpty() && skippedNotes.isNotEmpty()) {
            throw IllegalArgumentException(
                "Smart capture found no evidence regions. " +
                    (unmatched.takeIf { it.isNotEmpty() }?.let { "Unmatched: ${it.joinToString("; ")}. " } ?: "") +
                    "Skipped: ${skippedNotes.joinToString("; ")}. " +
                    "Use keyword or regex criteria for non-JSON content."
            )
        }
        val omittedRegions = if (allRegions.size > max_regions) allRegions.drop(max_regions) else emptyList()
        val capturedRegions = allRegions.take(max_regions)

        val blocks = mutableListOf<ContentBlock>()
        blocks += TextContent(
            "Smart capture over proxy history request_id $request_id: " +
                "${criteria.size} criteria, " +
                "${requestOutcome.matches.size} request matches, " +
                "${responseOutcome?.matches?.size ?: 0} response matches, " +
                "${capturedRegions.size} region screenshots " +
                "(${omittedRegions.size} regions omitted by max_regions=$max_regions). " +
                "Originals below are complete and unmodified."
        )
        blocks += TextContent("ORIGINAL REQUEST (${requestText.toByteArray().size} bytes):\n$requestText")
        blocks += TextContent(
            if (responseText != null) "ORIGINAL RESPONSE (${responseText.toByteArray().size} bytes):\n$responseText"
            else "ORIGINAL RESPONSE: <No response>"
        )

        val regionFiles = mutableListOf<String?>()
        val regionScrolls = mutableListOf<JsonObject>()
        val regionSearches = mutableListOf<String?>()
        val regionBoxes = mutableListOf<List<PlacedBox>>()
        val regionBoxNotes = mutableListOf<List<String>>()
        for ((regionIndex, region) in capturedRegions.withIndex()) {
            val regionId = "R${regionIndex + 1}"
            val sideText = if (region.side == EvidenceSide.RESPONSE) responseText!! else requestText
            // Raw objects: caret offsets index the original messages exactly.
            val requestObj = item.request()
            val responseObj = item.response()

            val caretTarget = region.startOffset
            val searchTerm = if (highlight_matches) {
                region.matches.first().matchedText.take(120).takeIf { it.isNotBlank() }
                    ?.takeIf { !redact_sensitive || EvidenceRedaction.redact(it) == it }
            } else null
            val redactTargets = if (redact_sensitive) {
                secretBoxTargets(requestText, BoxSide.REQUEST) +
                    (responseText?.let { secretBoxTargets(it, BoxSide.RESPONSE) }.orEmpty())
            } else emptyList()
            val outlineTargets = if (bounding_boxes) SmartEvidence.regionBoxTargets(region) else emptyList()
            val result = NativeEditorCapture.capture(
                api, requestObj, responseObj,
                capture_width, capture_height, layout,
                requestSearch = searchTerm?.takeIf { region.side == EvidenceSide.REQUEST },
                responseSearch = searchTerm?.takeIf { region.side == EvidenceSide.RESPONSE },
                requestCaret = caretTarget.takeIf { region.side == EvidenceSide.REQUEST },
                responseCaret = caretTarget.takeIf { region.side == EvidenceSide.RESPONSE },
                outlineTargets + redactTargets,
            ).copy(redacted = redact_sensitive)
            val placement = if (region.side == EvidenceSide.REQUEST) result.requestCaret else result.responseCaret
            if (placement == null || !placement.verified) {
                throw UnsupportedOperationException(
                    "Automated editor scrolling is unsupported for $regionId " +
                        "(${region.side.name.lowercase()} lines ${region.startLine}-${region.endLine}, " +
                        "offsets ${region.startOffset}-${region.endOffset}). Assisted manual capture: " +
                        "bring the Repeater tab for request_id $request_id to the foreground, scroll to " +
                        "the reported lines, and capture with burp_capture_evidence mode repeater " +
                        "or the ScreenShort extension."
                )
            }
            val finalPng = applyRedactionOverlay(result.png, result.placedBoxes)
            val redactedCount = result.placedBoxes.count { it.label == BoundingBox.REDACTED_LABEL }
            val outlineBoxes = result.placedBoxes.filter { it.label != BoundingBox.REDACTED_LABEL }
            val boxedPng = if (bounding_boxes && outlineBoxes.isNotEmpty()) {
                BoundingBox.drawBoxes(finalPng, outlineBoxes)
            } else finalPng
            val savedPath = output_prefix?.let {
                writeEvidenceFile("$it-${region.side.name.lowercase()}-${regionIndex + 1}.png", boxedPng, api)
            }
            regionFiles += savedPath
            regionScrolls += buildJsonObject {
                put("requested_offset", JsonPrimitive(placement.requested))
                put("applied_offset", JsonPrimitive(placement.applied))
                put("verified", JsonPrimitive(true))
                put("offset_basis", JsonPrimitive("original"))
            }
            val effectiveSearch = searchTerm
            regionSearches += effectiveSearch
            regionBoxes += listOf(outlineBoxes)
            regionBoxNotes += listOf(result.boxNotes.filter { it.startsWith(BoundingBox.HIGHLIGHT_LABEL) })
            blocks += TextContent(
                "$regionId ${region.side.name.lowercase()} lines ${region.startLine}-${region.endLine} " +
                    "(offsets ${region.startOffset}-${region.endOffset}): " +
                    "${region.matches.size} matches, caret verified at ${placement.applied}" +
                    (if (redact_sensitive) " with $redactedCount secret spans blacked out" else "") +
                    (if (bounding_boxes && outlineBoxes.isNotEmpty()) " with ${outlineBoxes.size} red boxes (3px #FF0000, sharp, transparent)" else "") + "." +
                    (savedPath?.let { " Saved to $it." } ?: "")
            )
            blocks += ImageContent(
                data = Base64.getEncoder().encodeToString(boxedPng), mimeType = "image/png"
            )
        }

        blocks += TextContent(
            buildSmartMetadata(
                requestId = request_id, criteria = criteria, goalNotes = goalNotes,
                regions = capturedRegions, omittedRegions = omittedRegions,
                unmatched = unmatched,
                unverified = requestOutcome.unverified + (responseOutcome?.unverified.orEmpty()),
                skipped = skippedNotes,
                capped = (requestOutcome.cappedCriteria + (responseOutcome?.cappedCriteria.orEmpty())).distinct(),
                scrolls = regionScrolls, files = regionFiles, searches = regionSearches,
                boxes = regionBoxes, boxNotes = regionBoxNotes,
                redactSensitive = redact_sensitive, maxRegions = max_regions,
                requestBytes = requestText.toByteArray().size,
                responseBytes = responseText?.toByteArray()?.size,
            )
        )
        blocks
    }

    mcpTool<BurpDiffEvidence>(
        "Automatic payload, diff, and exploit evidence highlighting. Compares a " +
            "baseline and a modified Proxy history pair (baseline_id, request_id), " +
            "detects the submitted payload from the request diff (or payload_hint), " +
            "locates verified response fragments for the stated objective, labels " +
            "the exploit SUCCESS / OBSERVED / INCONCLUSIVE / FAILED with confidence, " +
            "and captures native plus separately labeled annotated-derivative " +
            "screenshots. Modifications are never inferred without a valid baseline; " +
            "results are never fabricated."
    ) {
        val allowed = runBlocking {
            checkDataAccessOrDeny(DataAccessType.HTTP_HISTORY, config, api, "HTTP history diff capture")
        }
        if (!allowed) {
            return@mcpTool listOf(TextContent("HTTP history access denied by Burp Suite"))
        }
        DiffEvidence.validate(this)
        val baselineItem = try {
            NativeEvidence.resolveProxyItem(api, baseline_id)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Invalid baseline (${e.message}). Request modifications cannot be inferred without a valid baseline pair.")
        }
        val testItem = NativeEvidence.resolveProxyItem(api, request_id)
        val baseReq = baselineItem.request().toString()
        val baseRes = baselineItem.response()?.toString()
        val testReq = testItem.request().toString()
        val testRes = testItem.response()?.toString()

        val diff = RequestDiffer.diff(baseReq, testReq)
        if (diff.totalChanges == 0) {
            throw IllegalArgumentException(
                "Baseline and test requests are identical; no modification — and therefore " +
                    "no payload — can be identified. Verify the pair selection."
            )
        }
        val payload = PayloadEvidence.detectPayload(testReq, diff, payload_hint)
        val analysis = PayloadEvidence.analyzeResponse(testRes, baseRes, payload, objective, evidence_hint, testReq)
        val layout = NativeEvidence.parseLayout(this.layout)

        // Raw Burp objects: editors never receive rebuilt messages.
        val testRequestObj = testItem.request()
        val testResponseObj = testItem.response()
        val reqCaret = payload.startOffset
        // Prefer semantically strongest fragments for scroll+highlight:
        // verbatim reflection, then tester hint, then objective anchors, then deltas.
        val priorityEvidence = analysis.evidence.minByOrNull {
            when (it.kind) {
                EvidenceKind.PAYLOAD_REFLECTION -> 0
                EvidenceKind.HINT_MATCH -> 1
                EvidenceKind.OBJECTIVE_MATCH -> 2
                EvidenceKind.RESPONSE_DELTA -> 3
            }
        }
        val firstEvidence = priorityEvidence
        val resCaret = firstEvidence?.startOffset
        val reqSearch = payload.text.take(120)
            .takeIf { highlight_matches && it.isNotBlank() && (!redact_sensitive || EvidenceRedaction.redact(it) == it) }
        val resSearch = firstEvidence?.text?.take(120)
            ?.takeIf { highlight_matches && it.isNotBlank() && (!redact_sensitive || EvidenceRedaction.redact(it) == it) }

        // Bounding-box targets: modified params, payload, response evidence.
        // Editors hold raw messages, so original offsets apply directly.
        val boxNotes = mutableListOf<String>()
        val boxTargets = mutableListOf<BoxTarget>()
        if (bounding_boxes) {
            for (entry in diff.entries) {
                if (entry.kind == DiffKind.REMOVED) continue
                if (entry.afterStart < 0 || entry.afterEnd <= entry.afterStart) continue
                if (entry.afterEnd > testReq.length) continue
                val text = testReq.substring(entry.afterStart, entry.afterEnd)
                if (text.length !in 1..500) continue
                boxTargets += BoxTarget(
                    BoxSide.REQUEST, text, entry.afterStart, "modified ${entry.location}",
                    "modified ${entry.kind.name.lowercase()} ${entry.location}",
                )
            }
            boxTargets += BoxTarget(
                BoxSide.REQUEST, payload.text, payload.startOffset, "payload",
                "payload @${payload.location} offsets ${payload.startOffset}-${payload.endOffset}",
            )
            if (testRes != null) {
                val baselineResText = baseRes.orEmpty()
                for (fragment in analysis.evidence.take(8)) {
                    val text = fragment.text.take(500)
                    if (text.length < 3) continue
                    // Box only novel fragments: anything already visible in the
                    // baseline stays listed in evidence JSON but gets no box.
                    if (fragment.kind != EvidenceKind.RESPONSE_DELTA &&
                        baselineResText.contains(text)
                    ) {
                        boxNotes += "evidence@${fragment.startOffset}: also present in baseline, listed but not boxed"
                        continue
                    }
                    boxTargets += BoxTarget(
                        BoxSide.RESPONSE, text, fragment.startOffset, "evidence",
                        "evidence ${fragment.kind.name.lowercase()} line ${fragment.lineNumber} " +
                            "offsets ${fragment.startOffset}-${fragment.endOffset}: ${fragment.detail}",
                    )
                }
            }
            if (redact_sensitive) {
                boxTargets += secretBoxTargets(testReq, BoxSide.REQUEST)
                if (testRes != null) boxTargets += secretBoxTargets(testRes, BoxSide.RESPONSE)
            }
        }

        val result = NativeEditorCapture.capture(
            api, testRequestObj, testResponseObj,
            capture_width, capture_height, layout, reqSearch, resSearch, reqCaret, resCaret,
            boxTargets,
        ).copy(redacted = redact_sensitive)
        val reqPlacement = result.requestCaret
        if (reqPlacement == null || !reqPlacement.verified) {
            throw UnsupportedOperationException(
                "Automated editor scrolling to the payload is unsupported here. Assisted manual " +
                    "capture: bring the Repeater tab for request_id $request_id to the foreground, " +
                    "scroll to payload offset ${payload.startOffset} (${payload.location}), and capture " +
                    "with burp_capture_evidence mode repeater or the ScreenShort extension."
            )
        }
        if (resCaret != null && (result.responseCaret == null || !result.responseCaret.verified)) {
            throw UnsupportedOperationException(
                "Automated editor scrolling to the evidence region is unsupported here. Assisted manual " +
                    "capture: foreground the Repeater tab for request_id $request_id and capture with " +
                    "burp_capture_evidence mode repeater or the ScreenShort extension."
            )
        }

        val caption = listOf(
            "verdict: ${analysis.verdict} (confidence ${analysis.confidence}) — ${analysis.rationale.take(120)}",
            "payload @${payload.location} offsets ${payload.startOffset}-${payload.endOffset} enc=${payload.encodings}",
            "evidence: ${analysis.evidence.size} fragments" + (firstEvidence?.let {
                " first @lines ${it.lineNumber} offsets ${it.startOffset}-${it.endOffset}"
            } ?: ""),
            "offsets index the ORIGINAL messages; cropped viewport, see metadata",
        )
        // Raw editors mean the pure capture may show secrets: black out placed
        // redactions for every exported image. Outline boxes draw on top.
        val redactedBase = applyRedactionOverlay(result.png, result.placedBoxes)
        val redactedCount = result.placedBoxes.count { it.label == BoundingBox.REDACTED_LABEL }
        val outlineBoxes = result.placedBoxes.filter { it.label != BoundingBox.REDACTED_LABEL }
        val boxed = if (bounding_boxes) BoundingBox.drawBoxes(redactedBase, outlineBoxes) else null
        val numbered = BoundingBox.numberBoxes(outlineBoxes)
        val showLabels = box_labels && numbered.isNotEmpty()
        val legend = numbered.map { entry ->
            (if (entry.box.detail.isNotBlank()) entry.box.detail else entry.box.label) +
                " [${entry.box.side.name.lowercase()} @${entry.box.x},${entry.box.y} ${entry.box.width}x${entry.box.height}]"
        }
        val numberedDerivative = if (showLabels) {
            EvidenceOverlay.annotateNumbered(redactedBase, numbered, caption, legend)
        } else {
            EvidenceOverlay.annotate(redactedBase, caption)
        }
        val nativePath = output_prefix?.let { writeEvidenceFile("$it-native.png", redactedBase, api) }
        val derivativePath = output_prefix?.let {
            writeEvidenceFile("$it-annotated.png", numberedDerivative, api)
        }
        val boxedPath = if (boxed != null) output_prefix?.let { writeEvidenceFile("$it-boxed.png", boxed, api) } else null

        val blocks = mutableListOf<ContentBlock>()
        blocks += TextContent(
            "Diff evidence baseline $baseline_id -> test $request_id: ${diff.totalChanges} request changes, " +
                "payload '${payload.text.take(80)}' @${payload.location}, verdict ${analysis.verdict} " +
                "(${analysis.confidence}). Originals below are complete and unmodified."
        )
        blocks += TextContent("BASELINE REQUEST (${baseReq.toByteArray().size} bytes):\n$baseReq")
        blocks += TextContent(baseRes?.let { "BASELINE RESPONSE (${it.toByteArray().size} bytes):\n$it" } ?: "BASELINE RESPONSE: <No response>")
        blocks += TextContent("TEST REQUEST (${testReq.toByteArray().size} bytes):\n$testReq")
        blocks += TextContent(testRes?.let { "TEST RESPONSE (${it.toByteArray().size} bytes):\n$it" } ?: "TEST RESPONSE: <No response>")
        blocks += TextContent(buildDiffJson(diff, redact_sensitive))
        blocks += TextContent(buildPayloadAnalysisJson(analysis, redact_sensitive))
        blocks += TextContent(
            "NATIVE screenshot ${result.width}x${result.height}" +
                (nativePath?.let { ", saved to $it." } ?: ".") +
                " Pure Burp editor pixels of the raw messages" +
                (if (redactedCount > 0) " with $redactedCount secret spans blacked out" else "") +
                "; payload search '${reqSearch ?: "off"}', evidence search '${resSearch ?: "off"}'."
        )
        blocks += ImageContent(data = Base64.getEncoder().encodeToString(redactedBase), mimeType = "image/png")
        blocks += TextContent(
            "ANNOTATED DERIVATIVE (" + (if (showLabels) "numbered badges + labels + legend" else "caption only") +
                "; original PNG unmodified)" +
                (derivativePath?.let { ", saved to $it." } ?: ".")
        )
        blocks += ImageContent(data = Base64.getEncoder().encodeToString(numberedDerivative), mimeType = "image/png")
        if (boxed != null) {
            val boxSummary = if (outlineBoxes.isEmpty()) {
                "no boxes could be placed with verified coordinates"
            } else {
                "${outlineBoxes.size} red boxes (3px #FF0000, sharp, transparent)"
            }
            blocks += TextContent(
                "BOUNDED ANNOTATION (native pixels + verified red boxes; $boxSummary)" +
                    (boxedPath?.let { ", saved to $it." } ?: ".")
            )
            blocks += ImageContent(data = Base64.getEncoder().encodeToString(boxed), mimeType = "image/png")
        }
        blocks += TextContent(
            buildDiffMetadata(
                baselineId = baseline_id, requestId = request_id, diff = diff,
                analysis = analysis, redactSensitive = redact_sensitive,
                scrollReq = reqPlacement, scrollRes = result.responseCaret,
                nativePath = nativePath, derivativePath = derivativePath,
                boxedPath = boxedPath, boxes = numbered,
                boxNotes = boxNotes + result.boxNotes,
                labelsShown = showLabels,
                baselineBytes = baseReq.toByteArray().size to baseRes?.toByteArray()?.size,
                testBytes = testReq.toByteArray().size to testRes?.toByteArray()?.size,
            )
        )
        blocks
    }

    mcpPaginatedTool<GetOrganizerItems>("Displays items within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        api.organizer().items().asSequence().map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetOrganizerItemsRegex>("Displays items matching a specified regex within the Organizer tab") {
        val allowed = checkDataAccessOrDeny(DataAccessType.ORGANIZER, config, api, "Organizer")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("Organizer access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.organizer().items { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = checkDataAccessOrDeny(DataAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { encodeHistoryItem(it.toSerializableForm()) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

private fun renderEvidence(
    request: String,
    response: String?,
    title: String?,
    redactSecrets: Boolean,
    maxBodyCharacters: Int,
    highlights: List<EvidenceHighlight>,
    annotations: List<EvidenceAnnotation>,
    source: String,
): List<ContentBlock> {
    val image = EvidenceRenderer.render(
        request, response, title, redactSecrets, maxBodyCharacters, highlights, annotations
    )
    val summary = "Rendered $source as ${image.width}x${image.height} PNG " +
        "(${image.png.size} bytes; secrets ${if (redactSecrets) "redacted" else "not redacted"}; " +
        "${image.highlightMatches} highlight matches; ${image.annotationMatches} annotation callouts)."
    return listOf(
        TextContent(summary),
        ImageContent(data = Base64.getEncoder().encodeToString(image.png), mimeType = "image/png"),
    )
}

/**
 * Pixel-redaction targets for secret spans in a raw message. Editors always
 * show the original bytes; these boxes black out secrets after capture.
 */
private fun secretBoxTargets(message: String, side: BoxSide): List<BoxTarget> =
    EvidenceRedaction.secretSpans(message).mapNotNull { span ->
        if (span.first < 0 || span.last >= message.length) null
        else {
            val text = message.substring(span.first, span.last + 1)
            if (text.length in 1..500) BoxTarget(side, text, span.first, BoundingBox.REDACTED_LABEL) else null
        }
    }

/** Blacks out placed redaction boxes; outline boxes are left for the caller. */
private fun applyRedactionOverlay(png: ByteArray, boxes: List<PlacedBox>): ByteArray {
    val redactions = boxes.filter { it.label == BoundingBox.REDACTED_LABEL }
    return if (redactions.isEmpty()) png else BoundingBox.drawRedactions(png, redactions)
}

private fun renderNativeEvidence(
    result: NativeCaptureResult,
    finalPng: ByteArray,
    source: String,
    savedPath: String?,
    boundingBoxes: Boolean = true,
): List<ContentBlock> {
    val redactionCount = result.placedBoxes.count { it.label == BoundingBox.REDACTED_LABEL }
    val outlineBoxes = result.placedBoxes.filter { it.label != BoundingBox.REDACTED_LABEL }
    val highlightNotes = result.boxNotes.filter { it.startsWith(BoundingBox.HIGHLIGHT_LABEL) }
    val evidenceKind = when {
        !result.redacted -> "original evidence"
        redactionCount == 0 -> "original evidence (redaction requested; no secrets located)"
        else -> "original evidence with $redactionCount secret spans blacked out"
    }
    val summary = buildString {
        append("Captured native Burp HTTP editors for $source as ")
        append("${result.width}x${result.height} PNG (${finalPng.size} bytes; $evidenceKind). ")
        append("Editors show the raw Burp messages; nothing was added or rebuilt. ")
        append(NativeEditorCapture.VIEWPORT_NOTE + " ")
        if (result.requestSearchApplied != null) append("Native request search: '${result.requestSearchApplied}'. ")
        if (result.responseSearchApplied != null) append("Native response search: '${result.responseSearchApplied}'. ")
        if (boundingBoxes && outlineBoxes.isNotEmpty()) {
            append("${outlineBoxes.size} red boxes (3px #FF0000, sharp, transparent) drawn around verified highlight matches. ")
        }
        if (boundingBoxes && highlightNotes.isNotEmpty()) {
            append("Box notes: ${highlightNotes.joinToString("; ").take(500)}. ")
        }
        if (savedPath != null) append("Saved to $savedPath.")
    }
    return listOf(
        TextContent(summary),
        ImageContent(data = Base64.getEncoder().encodeToString(finalPng), mimeType = "image/png"),
    )
}

private fun buildDiffJson(diff: RequestDiff, redactSensitive: Boolean): String =
    buildJsonObject {
        put("total_changes", JsonPrimitive(diff.totalChanges))
        put("truncated", JsonPrimitive(diff.truncated))
        put(
            "entries",
            JsonArray(diff.entries.map { entry ->
                buildJsonObject {
                    put("kind", JsonPrimitive(entry.kind.name.lowercase()))
                    put("location", JsonPrimitive(entry.location))
                    entry.before?.let { put("before", JsonPrimitive(DiffEvidence.displayText(it.take(1000), redactSensitive))) }
                    entry.after?.let { put("after", JsonPrimitive(DiffEvidence.displayText(it.take(1000), redactSensitive))) }
                    put("auto_changed", JsonPrimitive(entry.autoChanged))
                }
            })
        )
    }.toString()

private fun buildPayloadAnalysisJson(
    analysis: ExploitAnalysis,
    redactSensitive: Boolean,
): String = buildJsonObject {
    put(
        "payload",
        buildJsonObject {
            put("text", JsonPrimitive(DiffEvidence.displayText(analysis.payload.text.take(1000), redactSensitive)))
            put("start_offset", JsonPrimitive(analysis.payload.startOffset))
            put("end_offset", JsonPrimitive(analysis.payload.endOffset))
            put("location", JsonPrimitive(analysis.payload.location))
            put("encodings", JsonArray(analysis.payload.encodings.map { JsonPrimitive(it) }))
            put("from_hint", JsonPrimitive(analysis.payload.fromHint))
            put("heuristic", JsonPrimitive(analysis.payload.heuristic))
            put("confidence", JsonPrimitive(analysis.payload.confidence))
        }
    )
    put(
        "evidence",
        JsonArray(analysis.evidence.map { fragment ->
            buildJsonObject {
                put("kind", JsonPrimitive(fragment.kind.name.lowercase()))
                put("start_offset", JsonPrimitive(fragment.startOffset))
                put("end_offset", JsonPrimitive(fragment.endOffset))
                put("text", JsonPrimitive(DiffEvidence.displayText(fragment.text.take(500), redactSensitive)))
                put("line", JsonPrimitive(fragment.lineNumber))
                put("detail", JsonPrimitive(fragment.detail))
            }
        })
    )
    put("verdict", JsonPrimitive(analysis.verdict.name.lowercase()))
    put("confidence", JsonPrimitive(analysis.confidence))
    put("rationale", JsonPrimitive(analysis.rationale))
}.toString()

private fun buildDiffMetadata(
    baselineId: String,
    requestId: String,
    diff: RequestDiff,
    analysis: ExploitAnalysis,
    redactSensitive: Boolean,
    scrollReq: CaretPlacement?,
    scrollRes: CaretPlacement?,
    nativePath: String?,
    derivativePath: String?,
    boxedPath: String?,
    boxes: List<net.portswigger.mcp.evidence.NumberedBox>,
    boxNotes: List<String>,
    labelsShown: Boolean,
    baselineBytes: Pair<Int, Int?>,
    testBytes: Pair<Int, Int?>,
): String = buildJsonObject {
    put("tool", JsonPrimitive("burp_diff_evidence"))
    put("baseline_id", JsonPrimitive(baselineId))
    put("request_id", JsonPrimitive(requestId))
    put("screenshot_mode", JsonPrimitive("native_editor"))
    put("total_changes", JsonPrimitive(diff.totalChanges))
    put("diff_truncated", JsonPrimitive(diff.truncated))
    put("verdict", JsonPrimitive(analysis.verdict.name.lowercase()))
    put("confidence", JsonPrimitive(analysis.confidence))
    put("volatile_excluded", JsonPrimitive(analysis.volatileExcluded))
    put("payload_offsets", JsonPrimitive("${analysis.payload.startOffset}-${analysis.payload.endOffset}"))
    put("payload_heuristic", JsonPrimitive(analysis.payload.heuristic))
    scrollReq?.let {
        put("scroll_request", buildJsonObject {
            put("requested_offset", JsonPrimitive(it.requested))
            put("applied_offset", JsonPrimitive(it.applied))
            put("verified", JsonPrimitive(it.verified))
        })
    }
    scrollRes?.let {
        put("scroll_response", buildJsonObject {
            put("requested_offset", JsonPrimitive(it.requested))
            put("applied_offset", JsonPrimitive(it.applied))
            put("verified", JsonPrimitive(it.verified))
        })
    }
    put("redaction_applied", JsonPrimitive(redactSensitive))
    put("redaction_scope", JsonPrimitive(if (redactSensitive) "pixel-overlay-on-raw-editors-originals-preserved" else "none"))
    nativePath?.let { put("native_file", JsonPrimitive(it)) }
    derivativePath?.let { put("annotated_derivative_file", JsonPrimitive(it)) }
    boxedPath?.let { put("boxed_file", JsonPrimitive(it)) }
    put(
        "boxes",
        JsonArray(boxes.map { entry ->
            buildJsonObject {
                put("marker", JsonPrimitive(entry.number))
                put("side", JsonPrimitive(entry.box.side.name.lowercase()))
                put("x", JsonPrimitive(entry.box.x))
                put("y", JsonPrimitive(entry.box.y))
                put("width", JsonPrimitive(entry.box.width))
                put("height", JsonPrimitive(entry.box.height))
                put("label", JsonPrimitive(entry.box.label))
                if (entry.box.detail.isNotBlank()) put("detail", JsonPrimitive(entry.box.detail.take(300)))
                put("style", JsonPrimitive("3px #FF0000 sharp transparent"))
            }
        })
    )
    put("box_notes", JsonArray(boxNotes.map { JsonPrimitive(it.take(300)) }))
    put("box_labels", JsonPrimitive(labelsShown))
    put("baseline_request_bytes", JsonPrimitive(baselineBytes.first))
    baselineBytes.second?.let { put("baseline_response_bytes", JsonPrimitive(it)) }
    put("test_request_bytes", JsonPrimitive(testBytes.first))
    testBytes.second?.let { put("test_response_bytes", JsonPrimitive(it)) }
    put(
        "viewport_note",
        JsonPrimitive(
            "Native PNG shows the visible editor viewport scrolled to payload/evidence; " +
                "the derivative only adds a labeled caption strip. Offsets index the original " +
                "messages; displayed text is redacted when redaction is enabled."
        )
    )
}.toString()

/**
 * Maps a region's original-text offset onto the effective editor text. When
 * redaction is off the offset is exact; otherwise the region's first match
 * text is re-located in the derivative, falling back to proportional mapping
 * (flagged in metadata via the offset_basis field).
 */
private fun matchToJson(match: LocatedMatch, redactSensitive: Boolean): JsonObject = buildJsonObject {
    put("criterion", JsonPrimitive("#${match.criterionIndex} ${match.type.name.lowercase()} '${match.expression}'"))
    put("start_offset", JsonPrimitive(match.startOffset))
    put("end_offset", JsonPrimitive(match.endOffset))
    val text = if (redactSensitive) EvidenceRedaction.redact(match.matchedText) else match.matchedText
    put("text", JsonPrimitive(text.take(500)))
    put("line", JsonPrimitive(match.lineNumber))
    match.nodePath?.let { put("node_path", JsonPrimitive(it)) }
}

private fun buildSmartMetadata(
    requestId: String,
    criteria: List<MatchCriterion>,
    goalNotes: List<String>,
    regions: List<EvidenceRegion>,
    omittedRegions: List<EvidenceRegion>,
    unmatched: List<String>,
    unverified: List<String>,
    skipped: List<String>,
    capped: List<Int>,
    scrolls: List<JsonObject>,
    files: List<String?>,
    searches: List<String?>,
    boxes: List<List<PlacedBox>> = emptyList(),
    boxNotes: List<List<String>> = emptyList(),
    redactSensitive: Boolean,
    maxRegions: Int,
    requestBytes: Int,
    responseBytes: Int?,
): String = buildJsonObject {
    put("tool", JsonPrimitive("burp_smart_evidence"))
    put("request_id", JsonPrimitive(requestId))
    put("screenshot_mode", JsonPrimitive("native_editor"))
    put("redaction_applied", JsonPrimitive(redactSensitive))
    put("redaction_scope", JsonPrimitive(if (redactSensitive) "pixel-overlay-on-raw-editors-originals-preserved" else "none"))
    put("criteria", JsonArray(criteria.map {
        JsonPrimitive("#${it.index} ${it.type.name.lowercase()} '${it.expression}' caseSensitive=${it.caseSensitive}")
    }))
    put("goal_notes", JsonArray(goalNotes.map { JsonPrimitive(it) }))
    put("unmatched_criteria", JsonArray(unmatched.map { JsonPrimitive(it) }))
    put("skipped", JsonArray(skipped.map { JsonPrimitive(it) }))
    put("unverified_nodes", JsonArray(unverified.map { JsonPrimitive(it) }))
    put("capped_criteria", JsonArray(capped.map { JsonPrimitive(it) }))
    put(
        "regions",
        JsonArray(regions.mapIndexed { i, region ->
            buildJsonObject {
                put("id", JsonPrimitive("R${i + 1}"))
                put("side", JsonPrimitive(region.side.name.lowercase()))
                put("start_line", JsonPrimitive(region.startLine))
                put("end_line", JsonPrimitive(region.endLine))
                put("start_offset", JsonPrimitive(region.startOffset))
                put("end_offset", JsonPrimitive(region.endOffset))
                put("matches", JsonArray(region.matches.map { matchToJson(it, redactSensitive) }))
                put("scroll", scrolls[i])
                files[i]?.let { put("file", JsonPrimitive(it)) }
                searches[i]?.let { put("highlight", JsonPrimitive(it.take(200))) }
                if (i < boxes.size) {
                    put(
                        "boxes",
                        JsonArray(boxes[i].map { box ->
                            buildJsonObject {
                                put("side", JsonPrimitive(box.side.name.lowercase()))
                                put("x", JsonPrimitive(box.x))
                                put("y", JsonPrimitive(box.y))
                                put("width", JsonPrimitive(box.width))
                                put("height", JsonPrimitive(box.height))
                                put("label", JsonPrimitive(box.label))
                                put("style", JsonPrimitive("3px #FF0000 sharp transparent"))
                            }
                        })
                    )
                }
                if (i < boxNotes.size) {
                    put("box_notes", JsonArray(boxNotes[i].map { JsonPrimitive(it.take(300)) }))
                }
            }
        })
    )
    put(
        "omitted_regions",
        JsonArray(omittedRegions.map {
            JsonPrimitive(
                "${it.side.name.lowercase()} lines ${it.startLine}-${it.endLine} " +
                    "offsets ${it.startOffset}-${it.endOffset} (${it.matches.size} matches; " +
                    "excluded by max_regions=$maxRegions)"
            )
        })
    )
    put("original_request_bytes", JsonPrimitive(requestBytes))
    responseBytes?.let { put("original_response_bytes", JsonPrimitive(it)) }
    put(
        "viewport_note",
        JsonPrimitive(
            "Each PNG shows the visible native-editor viewport scrolled to its region; " +
                "not the entire message. Originals above are complete and unmodified."
        )
    )
}.toString()

private fun writeEvidenceFile(path: String, png: ByteArray, api: MontoyaApi): String {    val file = File(path)
    file.parentFile?.mkdirs()
    file.writeBytes(png)
    api.logging().logToOutput("MCP wrote native evidence PNG to ${file.absolutePath} (${png.size} bytes)")
    return file.absolutePath
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTabHttp2(
    val tabName: String?,
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class ScreenshotProxyHttpHistory(
    val offset: Int,
    val redactSecrets: Boolean = true,
    val maxBodyCharacters: Int = 4_000,
    val title: String? = null,
    val highlights: List<EvidenceHighlight> = emptyList(),
    val annotations: List<EvidenceAnnotation> = emptyList(),
)

@Serializable
data class ScreenshotProxyHttpHistoryRegex(
    val regex: String,
    val matchOffset: Int = 0,
    val redactSecrets: Boolean = true,
    val maxBodyCharacters: Int = 4_000,
    val title: String? = null,
    val highlights: List<EvidenceHighlight> = emptyList(),
    val annotations: List<EvidenceAnnotation> = emptyList(),
)

@Serializable
data class GetOrganizerItems(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetOrganizerItemsRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated

@Serializable
data class GenerateCollaboratorPayload(
    val customData: String? = null
)

@Serializable
data class GetCollaboratorInteractions(
    val payloadId: String? = null
)
