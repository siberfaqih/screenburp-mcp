package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine
import burp.api.montoya.collaborator.*
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.Http
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpProtocol
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.ui.UserInterface
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import burp.api.montoya.utilities.Base64Utils
import burp.api.montoya.utilities.RandomUtils
import burp.api.montoya.utilities.URLUtils
import burp.api.montoya.utilities.Utilities
import io.mockk.*
import java.net.InetAddress
import java.time.ZonedDateTime
import java.util.Optional
import io.modelcontextprotocol.kotlin.sdk.types.CallToolResult
import io.modelcontextprotocol.kotlin.sdk.types.ImageContent
import io.modelcontextprotocol.kotlin.sdk.types.TextContent
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.KtorServerManager
import net.portswigger.mcp.ServerState
import net.portswigger.mcp.TestSseMcpClient
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.HttpRequestResponse
import net.portswigger.mcp.schema.toSerializableForm
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.net.ServerSocket
import javax.imageio.ImageIO
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextArea

class ToolsKtTest {
    
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api)
    private val testPort = findAvailablePort()
    private var serverStarted = false
    private val config: McpConfig
    private val mockHeaders = mutableListOf<HttpHeader>()
    private val capturedRequest = slot<HttpRequest>()

    init {
        val persistedObject = mockk<PersistedObject>().apply {
            every { getBoolean("enabled") } returns true
            every { getBoolean("configEditingTooling") } returns true
            every { getBoolean("requireHttpRequestApproval") } returns false
            every { getBoolean("requireDataAccessApproval") } returns false
            every { getBoolean("_alwaysAllowHttpHistory") } returns false
            every { getBoolean("_alwaysAllowWebSocketHistory") } returns false
            every { getBoolean("_alwaysAllowOrganizer") } returns false
            every { getString("host") } returns "127.0.0.1"
            every { getString("_autoApproveTargets") } returns ""
            every { getInteger("port") } returns testPort
            every { setBoolean(any(), any()) } returns Unit
            every { setString(any(), any()) } returns Unit
            every { setInteger(any(), any()) } returns Unit
        }
        val mockLogging = mockk<Logging>().apply {
            every { logToError(any<String>()) } returns Unit
            every { logToOutput(any<String>()) } returns Unit
        }

        config = McpConfig(persistedObject, mockLogging)
        
        mockkStatic(HttpHeader::class)
        mockkStatic(burp.api.montoya.http.HttpService::class)
        mockkStatic(HttpRequest::class)
    }

    private fun CallToolResult?.expectTextContent(
        expected: String? = null,
    ): String {
        assertNotNull(this, "Tool result cannot be null")
        val result = this!!

        val content = result.content
        assertNotNull(content, "Tool result content cannot be null")

        val nonNullContent = content
        assertEquals(1, nonNullContent.size, "Expected exactly one content element")

        val textContent = nonNullContent.firstOrNull() as? TextContent
        assertNotNull(textContent, "Expected content to be TextContent")

        val text = textContent!!.text
        assertNotNull(text, "Text content cannot be null")

        if (expected != null) {
            assertEquals(expected, text, "Text content doesn't match expected value")
        }

        return text!!
    }

    private fun setupHttpHeaderMocks() {
        every { HttpHeader.httpHeader(any<String>(), any<String>()) } answers {
            val name = firstArg<String>()
            val value = secondArg<String>()
            mockk<HttpHeader>().also {
                every { it.name() } returns name
                every { it.value() } returns value
                mockHeaders.add(it)
            }
        }

        every { burp.api.montoya.http.HttpService.httpService(any(), any(), any()) } answers {
            val host = firstArg<String>()
            val port = secondArg<Int>()
            val secure = thirdArg<Boolean>()
            mockk<burp.api.montoya.http.HttpService>().also {
                every { it.host() } returns host
                every { it.port() } returns port
                every { it.secure() } returns secure
            }
        }
    }
    
    @BeforeEach
    fun setup() {
        setupHttpHeaderMocks()

        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")
            assertNotNull(client.ping(), "Ping should return a result")
        }
    }

    private fun findAvailablePort() = ServerSocket(0).use { it.localPort }

    @AfterEach
    fun tearDown() {
        runBlocking { if (client.isConnected()) client.close() }
        serverManager.stop {}
    }

    @Nested
    inner class HttpToolsTests {
        @Test
        fun `http1 line endings should be normalized`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpResponse.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { httpService.sendRequest(capture(capturedRequest)) } returns httpResponse

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\nHost: example.com\n\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { httpService.sendRequest(any<HttpRequest>()) }
            assertEquals("GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n", capturedRequest.captured.toString(), "Request body should match")
        }

        @Test
        fun `http1 request should handle no response`() {
            val httpService = mockk<Http>()
            val contentSlot = slot<String>()

            every { HttpRequest.httpRequest(any(), capture(contentSlot)) } answers {
                val content = secondArg<String>()
                mockk<HttpRequest>().also {
                    every { it.toString() } returns content
                }
            }
            every { api.http() } returns httpService
            every { httpService.sendRequest(any()) } returns null

            runBlocking {
                val result = client.callTool(
                    "send_http1_request", mapOf(
                        "content" to "GET /foo HTTP/1.1\r\nHost: example.com\r\n\r\n",
                        "targetHostname" to "example.com",
                        "targetPort" to 80,
                        "usesHttps" to false
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }

        @Test
        fun `http2 request should be formatted properly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val requestSlot = slot<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK\r\nContent-Type: text/plain\r\n\r\nResponse body"
            every { api.http() } returns httpService
            every { httpService.sendRequest(capture(requestSlot), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "authority" to "example.com", "scheme" to "https", "method" to "GET", ":path" to "/test"
            )
            val headers = mapOf(
                "User-Agent" to "Test Agent", "Accept" to "*/*"
            )
            val requestBody = "Test body"

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                val text = result.expectTextContent()
                assertFalse(text.contains("Error"), 
                    "Expected success response but got error: $text")
            }

            verify(exactly = 1) { HttpRequest.http2Request(any(), any(), any<String>()) }
            
            assertEquals("Test body", bodySlot.captured, "Request body should match")
            
            val pseudoHeaderList = headersSlot.captured.filter { it.name().startsWith(":") }
            val normalHeaderList = headersSlot.captured.filter { !it.name().startsWith(":") }
            
            assertTrue(pseudoHeaderList.any { it.name() == ":scheme" && it.value() == "https" })
            assertTrue(pseudoHeaderList.any { it.name() == ":method" && it.value() == "GET" })
            assertTrue(pseudoHeaderList.any { it.name() == ":path" && it.value() == "/test" })
            assertTrue(pseudoHeaderList.any { it.name() == ":authority" && it.value() == "example.com" })
            
            assertTrue(normalHeaderList.any { it.name() == "user-agent" && it.value() == "Test Agent" })
            assertTrue(normalHeaderList.any { it.name() == "accept" && it.value() == "*/*" })
        }
        
        @Test
        fun `http2 request should handle null response`() {
            val httpService = mockk<Http>()
            val httpRequest = mockk<HttpRequest>()

            every { HttpRequest.http2Request(any(), any(), any<String>()) } returns httpRequest
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns null

            val pseudoHeaders = mapOf("method" to "GET", "path" to "/test")
            val headers = mapOf("User-Agent" to "Test Agent")

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                result.expectTextContent("<no response>")
            }
        }
        
        @Test
        fun `http2 pseudo headers should be ordered correctly`() {
            val httpService = mockk<Http>()
            val httpResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), any<String>()) } returns httpRequest
            every { httpResponse.toString() } returns "HTTP/2 200 OK"
            every { api.http() } returns httpService
            every { httpService.sendRequest(any(), HttpMode.HTTP_2) } returns httpResponse

            val pseudoHeaders = mapOf(
                "path" to "/test",
                ":authority" to "example.com", 
                "method" to "GET",
                "scheme" to "https"
            )

            runBlocking {
                val result = client.callTool(
                    "send_http2_request", mapOf(
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(emptyMap<String, String>()),
                        "requestBody" to "",
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )
                
                delay(100)
                assertNotNull(result)
            }
            
            val pseudoHeaderNames = headersSlot.captured
                .filter { it.name().startsWith(":") }
                .map { it.name() }
            
            val expectedOrder = listOf(":scheme", ":method", ":path", ":authority")
            for (i in 0 until minOf(expectedOrder.size, pseudoHeaderNames.size)) {
                assertEquals(expectedOrder[i], pseudoHeaderNames[i],
                    "Pseudo headers should follow the order: scheme, method, path, authority")
            }
        }

        @Test
        fun `create repeater tab http2 should build http2 request`() {
            val repeater = mockk<burp.api.montoya.repeater.Repeater>(relaxed = true)
            val httpRequest = mockk<HttpRequest>()
            val headersSlot = slot<List<HttpHeader>>()
            val bodySlot = slot<String>()

            every { HttpRequest.http2Request(any(), capture(headersSlot), capture(bodySlot)) } returns httpRequest
            every { api.repeater() } returns repeater

            val pseudoHeaders = mapOf(
                "method" to "POST", "path" to "/api/x", "authority" to "example.com", "scheme" to "https"
            )
            val headers = mapOf("Content-Type" to "application/json")
            val requestBody = "{\"k\":\"v\"}"

            runBlocking {
                val result = client.callTool(
                    "create_repeater_tab_http2", mapOf(
                        "tabName" to "h2-tab",
                        "pseudoHeaders" to Json.encodeToJsonElement(pseudoHeaders),
                        "headers" to Json.encodeToJsonElement(headers),
                        "requestBody" to requestBody,
                        "targetHostname" to "example.com",
                        "targetPort" to 443,
                        "usesHttps" to true
                    )
                )

                delay(100)
                assertNotNull(result)
            }

            verify(exactly = 1) { repeater.sendToRepeater(httpRequest, "h2-tab") }
            assertEquals("{\"k\":\"v\"}", bodySlot.captured, "Request body should be passed through unchanged")

            val pseudoHeaderNames = headersSlot.captured.filter { it.name().startsWith(":") }.map { it.name() }
            assertEquals(listOf(":scheme", ":method", ":path", ":authority"), pseudoHeaderNames)
            assertTrue(headersSlot.captured.any { it.name() == "content-type" && it.value() == "application/json" })
        }
    }

    @Nested
    inner class UtilityToolsTests {
        @Test
        fun `url encode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.encode(any<String>()) } returns "test+string+with+spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_encode", mapOf(
                        "content" to "test string with spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test+string+with+spaces")
            }
            
            verify(exactly = 1) { urlUtils.encode(any<String>()) }
        }
        
        @Test
        fun `url decode should work properly`() {
            val urlUtils = mockk<URLUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.urlUtils() } returns urlUtils
            every { urlUtils.decode(any<String>()) } returns "test string with spaces"
            
            runBlocking {
                val result = client.callTool(
                    "url_decode", mapOf(
                        "content" to "test+string+with+spaces"
                    )
                )
                
                delay(100)
                result.expectTextContent("test string with spaces")
            }
            
            verify(exactly = 1) { urlUtils.decode(any<String>()) }
        }
        
        @Test
        fun `base64 encode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.encodeToString(any<String>()) } returns "dGVzdCBzdHJpbmc="
            
            runBlocking {
                val result = client.callTool(
                    "base64_encode", mapOf(
                        "content" to "test string"
                    )
                )
                
                delay(100)
                result.expectTextContent("dGVzdCBzdHJpbmc=")
            }
            
            verify(exactly = 1) { base64Utils.encodeToString(any<String>()) }
        }
        
        @Test
        fun `base64 decode should work properly`() {
            val base64Utils = mockk<Base64Utils>()
            val utilities = mockk<Utilities>()
            val burpByteArray = mockk<ByteArray>()
            
            every { api.utilities() } returns utilities
            every { utilities.base64Utils() } returns base64Utils
            every { base64Utils.decode(any<String>()) } returns burpByteArray
            every { burpByteArray.toString() } returns "test string"
            
            runBlocking {
                val result = client.callTool(
                    "base64_decode", mapOf(
                        "content" to "dGVzdCBzdHJpbmc="
                    )
                )
                
                delay(100)
                result.expectTextContent("test string")
            }
            
            verify(exactly = 1) { base64Utils.decode(any<String>()) }
        }
        
        @Test
        fun `generate random string should work properly`() {
            val randomUtils = mockk<RandomUtils>()
            val utilities = mockk<Utilities>()
            
            every { api.utilities() } returns utilities
            every { utilities.randomUtils() } returns randomUtils
            every { randomUtils.randomString(any<Int>(), any<String>()) } returns "1a2b3c1a2b"
            
            runBlocking {
                val result = client.callTool(
                    "generate_random_string", mapOf(
                        "length" to 10,
                        "characterSet" to "abc123"
                    )
                )
                
                delay(100)
                result.expectTextContent("1a2b3c1a2b")
            }
            
            verify(exactly = 1) { randomUtils.randomString(any<Int>(), any<String>()) }
        }
    }
    
    @Nested
    inner class ConfigurationToolsTests {
        @Test
        fun `set task execution engine state should work properly`() {
            val taskExecutionEngine = mockk<TaskExecutionEngine>()
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.taskExecutionEngine() } returns taskExecutionEngine
            every { taskExecutionEngine.state = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now running")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.RUNNING }
            
            clearMocks(taskExecutionEngine, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_task_execution_engine_state", mapOf(
                        "running" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Task execution engine is now paused")
            }
            
            verify(exactly = 1) { taskExecutionEngine.state = TaskExecutionEngine.TaskExecutionEngineState.PAUSED }
        }
        
        @Test
        fun `set proxy intercept state should work properly`() {
            val proxy = mockk<Proxy>()
            
            every { api.proxy() } returns proxy
            every { proxy.enableIntercept() } just runs
            every { proxy.disableIntercept() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to true
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been enabled")
            }
            
            verify(exactly = 1) { proxy.enableIntercept() }
            
            clearMocks(proxy, answers = false)
            
            runBlocking {
                val result = client.callTool(
                    "set_proxy_intercept_state", mapOf(
                        "intercepting" to false
                    )
                )
                
                delay(100)
                result.expectTextContent("Intercept has been disabled")
            }
            
            verify(exactly = 1) { proxy.disableIntercept() }
        }
        
        @Test
        fun `config editing tools should respect config settings`() {
            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { api.logging().logToOutput(any()) } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("Project configuration has been applied")
            }
            
            verify(exactly = 1) { burpSuite.importProjectOptionsFromJson(any()) }
            
            clearMocks(burpSuite, answers = false)
            
            every { config.configEditingTooling } returns false
            
            runBlocking {
                
                val result = client.callTool(
                    "set_project_options", mapOf(
                        "json" to "{\"test\": true}"
                    )
                )
                
                delay(100)
                result.expectTextContent("User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'")
            }
            
            verify(exactly = 0) { burpSuite.importProjectOptionsFromJson(any()) }
        }
    }

    @Nested
    inner class EditorTests {
        @Test
        fun `get active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `get active editor contents should return text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.text } returns "Editor content"
            
            runBlocking {
                val result = client.callTool("get_active_editor_contents", emptyMap())
                
                delay(100)
                result.expectTextContent("Editor content")
            }
        }
        
        @Test
        fun `set active editor contents should handle no editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            every { getActiveEditor(api) } returns null
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<No active editor>")
            }
        }
        
        @Test
        fun `set active editor contents should handle non-editable editor`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns false
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("<Current editor is not editable>")
            }
        }
        
        @Test
        fun `set active editor contents should update text`() {
            mockkStatic("net.portswigger.mcp.tools.ToolsKt")
            
            val textArea = mockk<JTextArea>()
            every { getActiveEditor(api) } returns textArea
            every { textArea.isEditable } returns true
            every { textArea.text = any() } just runs
            
            runBlocking {
                val result = client.callTool(
                    "set_active_editor_contents", mapOf(
                        "text" to "New content"
                    )
                )
                
                delay(100)
                result.expectTextContent("Editor text has been set")
            }
            
            verify(exactly = 1) { textArea.text = "New content" }
        }
    }
    
    @Nested
    inner class PaginatedToolsTests {
        @Test
        fun `screenshot proxy history should return MCP image content`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val response = mockk<HttpResponse>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)
            every { historyItem.request() } returns request
            every { historyItem.response() } returns response
            every { request.toString() } returns "GET /proof HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer secret\r\n\r\n"
            every { response.toString() } returns "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nproof"

            runBlocking {
                val result = client.callTool(
                    "screenshot_proxy_http_history",
                    mapOf(
                        "offset" to 0,
                        "title" to "Test proof",
                        "highlights" to listOf(mapOf("match" to "HTTP/1.1 200", "color" to "green")),
                        "annotations" to listOf(
                            mapOf("match" to "proof", "label" to "Successful evidence", "color" to "blue")
                        ),
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                assertEquals(2, result.content.size)
                assertTrue(result.content[0] is TextContent)
                assertTrue((result.content[0] as TextContent).text!!.contains("1 highlight matches"))
                assertTrue((result.content[0] as TextContent).text!!.contains("1 annotation callouts"))
                val image = result.content[1] as? ImageContent
                assertNotNull(image)
                assertEquals("image/png", image!!.mimeType)
                val png = java.util.Base64.getDecoder().decode(image.data)
                assertArrayEquals(
                    byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
                    png.take(8).toByteArray()
                )
            }
        }

        @Test
        fun `burp capture evidence should render native editors as MCP image`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val response = mockk<HttpResponse>()
            val ui = mockk<UserInterface>(relaxed = true)
            val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
            val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)
            every { historyItem.request() } returns request
            every { historyItem.response() } returns response
            every { api.userInterface() } returns ui
            every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
            every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
            every { requestEditor.uiComponent() } returns JPanel().apply { add(JLabel("req")) }
            every { responseEditor.uiComponent() } returns JPanel().apply { add(JLabel("res")) }

            runBlocking {
                val result = client.callTool(
                    "burp_capture_evidence",
                    mapOf(
                        "request_id" to "0",
                        "mode" to "native_editor",
                        "layout" to "side_by_side",
                        "theme" to "inherit",
                        "capture_width" to 800,
                        "capture_height" to 600,
                        "highlight" to mapOf(
                            "request" to listOf("mechanic_api"),
                            "response" to listOf("HTTP/1.1 200")
                        ),
                        "redact_sensitive" to false,
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                assertEquals(2, result.content.size)
                val text = (result.content[0] as TextContent).text!!
                assertTrue(text.contains("native Burp HTTP editors"))
                assertTrue(text.contains("Viewport capture"))
                assertTrue(text.contains("original evidence"))
                val image = result.content[1] as? ImageContent
                assertNotNull(image)
                assertEquals("image/png", image!!.mimeType)
                val png = java.util.Base64.getDecoder().decode(image.data)
                assertArrayEquals(
                    byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
                    png.take(8).toByteArray()
                )
            }

            verify(exactly = 1) { requestEditor.setRequest(request) }
            verify(exactly = 1) { responseEditor.setResponse(response) }
        }

        @Test
        fun `burp capture evidence should reject unknown request ids explicitly`() {
            val proxy = mockk<Proxy>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "burp_capture_evidence",
                    mapOf("request_id" to "42")
                )
                assertNotNull(result)
                assertTrue(result!!.isError == true)
                val text = (result.content[0] as TextContent).text!!
                assertTrue(text.contains("No Proxy HTTP history item exists at offset 42"))
            }
        }

        @Test
        fun `burp capture evidence should reject unsupported themes explicitly`() {
            runBlocking {
                val result = client.callTool(
                    "burp_capture_evidence",
                    mapOf("request_id" to "0", "theme" to "dark")
                )
                assertNotNull(result)
                assertTrue(result!!.isError == true)
                val text = (result.content[0] as TextContent).text!!
                assertTrue(text.contains("not supported"))
            }
        }

        @Test
        fun `burp smart evidence should capture regions with metadata and originals`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val response = mockk<HttpResponse>()
            val ui = mockk<UserInterface>(relaxed = true)
            val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
            val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
            val requestText = "POST /fetch HTTP/1.1\r\nHost: example.test\r\n\r\n{\"url\":\"http://evil.example/hook\"}"
            val responseText = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nline1\nfetched evil.example content here\nline3"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)
            every { historyItem.request() } returns request
            every { historyItem.response() } returns response
            every { request.toString() } returns requestText
            every { response.toString() } returns responseText
            every { api.userInterface() } returns ui
            every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
            every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
            every { requestEditor.uiComponent() } returns JPanel().apply { add(JLabel("req")) }
            every { responseEditor.uiComponent() } returns JPanel().apply { add(JLabel("res")) }
            val caretSlot = slot<Int>()
            every { responseEditor.setCaretPosition(capture(caretSlot)) } just runs
            every { responseEditor.caretPosition() } answers { caretSlot.captured }

            runBlocking {
                val result = client.callTool(
                    "burp_smart_evidence",
                    mapOf(
                        "request_id" to "0",
                        "select" to listOf(mapOf("type" to "keyword", "expression" to "fetched evil.example")),
                        "context_lines" to 1,
                        "capture_width" to 800,
                        "capture_height" to 600,
                        "redact_sensitive" to false,
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                assertEquals(6, result.content.size)
                assertTrue((result.content[1] as TextContent).text!!.contains(requestText))
                assertTrue((result.content[2] as TextContent).text!!.contains("fetched evil.example content here"))
                val image = result.content[4] as? ImageContent
                assertNotNull(image)
                assertEquals("image/png", image!!.mimeType)
                val metadata = Json.parseToJsonElement((result.content[5] as TextContent).text!!).jsonObject
                assertEquals("native_editor", metadata["screenshot_mode"]!!.jsonPrimitive.content)
                assertEquals(false, metadata["redaction_applied"]!!.jsonPrimitive.boolean)
                val regions = metadata["regions"]!!.jsonArray
                assertEquals(1, regions.size)
                val region = regions[0].jsonObject
                assertEquals("response", region["side"]!!.jsonPrimitive.content)
                assertEquals(true, region["scroll"]!!.jsonObject["verified"]!!.jsonPrimitive.boolean)
                assertEquals("original", region["scroll"]!!.jsonObject["offset_basis"]!!.jsonPrimitive.content)
                val match = region["matches"]!!.jsonArray[0].jsonObject
                assertEquals("fetched evil.example", match["text"]!!.jsonPrimitive.content)
                assertTrue(match["start_offset"]!!.jsonPrimitive.int > 0)
            }

            verify(exactly = 1) { responseEditor.setResponse(response) }
        }

        @Test
        fun `burp smart evidence should report unmatched criteria explicitly`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)
            every { historyItem.request() } returns request
            every { historyItem.response() } returns null
            every { request.toString() } returns "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

            runBlocking {
                val result = client.callTool(
                    "burp_smart_evidence",
                    mapOf(
                        "request_id" to "0",
                        "select" to listOf(mapOf("type" to "keyword", "expression" to "zzz-no-such-evidence")),
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                assertEquals(4, result.content.size)
                assertTrue(result.content.none { it is ImageContent })
                val metadata = Json.parseToJsonElement((result.content[3] as TextContent).text!!).jsonObject
                assertEquals(0, metadata["regions"]!!.jsonArray.size)
                assertTrue(
                    metadata["unmatched_criteria"]!!.jsonArray.any {
                        it.jsonPrimitive.content.contains("zzz-no-such-evidence")
                    }
                )
            }
        }

        @Test
        fun `burp smart evidence should offer manual capture when scrolling fails`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            val response = mockk<HttpResponse>()
            val ui = mockk<UserInterface>(relaxed = true)
            val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
            // Relaxed editor ignores caret placement: read-back stays 0.
            val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)
            every { historyItem.request() } returns request
            every { historyItem.response() } returns response
            every { request.toString() } returns "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"
            every { response.toString() } returns "HTTP/1.1 200 OK\r\n\r\n" +
                (1..20).joinToString("\n") { "filler $it" } + "\nneedle here"
            every { api.userInterface() } returns ui
            every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
            every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
            every { requestEditor.uiComponent() } returns JPanel()
            every { responseEditor.uiComponent() } returns JPanel()

            runBlocking {
                val result = client.callTool(
                    "burp_smart_evidence",
                    mapOf(
                        "request_id" to "0",
                        "select" to listOf(mapOf("type" to "keyword", "expression" to "needle")),
                        "redact_sensitive" to false,
                    )
                )
                assertNotNull(result)
                assertTrue(result!!.isError == true)
                val text = (result.content[0] as TextContent).text!!
                assertTrue(text.contains("Assisted manual capture"))
            }
        }

        @Test
        fun `burp diff evidence should report verdict with native and derivative images`() {
            val proxy = mockk<Proxy>()
            val baselineItem = mockk<ProxyHttpRequestResponse>()
            val testItem = mockk<ProxyHttpRequestResponse>()
            val baseReq = mockk<HttpRequest>()
            val baseRes = mockk<HttpResponse>()
            val testReq = mockk<HttpRequest>()
            val testRes = mockk<HttpResponse>()
            val ui = mockk<UserInterface>(relaxed = true)
            val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
            val responseEditor = mockk<HttpResponseEditor>(relaxed = true)
            val baseReqText = "POST /api/contact HTTP/1.1\r\nHost: x\r\n\r\n{\"url\":\"http://safe.test/r\"}"
            val testReqText = "POST /api/contact HTTP/1.1\r\nHost: x\r\n\r\n{\"url\":\"http://evil.test/poc\"}"
            val baseResText = "HTTP/1.1 200 OK\r\n\r\n{\"fetched\":\"nothing\"}"
            val testResText = "HTTP/1.1 200 OK\r\n\r\n{\"fetched\":\"http://evil.test/poc content\"}"
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(baselineItem, testItem)
            every { baselineItem.request() } returns baseReq
            every { baselineItem.response() } returns baseRes
            every { testItem.request() } returns testReq
            every { testItem.response() } returns testRes
            every { baseReq.toString() } returns baseReqText
            every { baseRes.toString() } returns baseResText
            every { testReq.toString() } returns testReqText
            every { testRes.toString() } returns testResText
            every { api.userInterface() } returns ui
            every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
            every { ui.createHttpResponseEditor(EditorOptions.READ_ONLY) } returns responseEditor
            every { requestEditor.uiComponent() } returns JPanel().apply { add(JLabel("req")) }
            every { responseEditor.uiComponent() } returns JPanel().apply { add(JLabel("res")) }
            val reqCaret = slot<Int>()
            val resCaret = slot<Int>()
            every { requestEditor.setCaretPosition(capture(reqCaret)) } just runs
            every { requestEditor.caretPosition() } answers { reqCaret.captured }
            every { responseEditor.setCaretPosition(capture(resCaret)) } just runs
            every { responseEditor.caretPosition() } answers { resCaret.captured }

            runBlocking {
                val result = client.callTool(
                    "burp_diff_evidence",
                    mapOf(
                        "baseline_id" to "0",
                        "request_id" to "1",
                        "objective" to "server fetches the supplied url",
                        "capture_width" to 800,
                        "capture_height" to 600,
                        "redact_sensitive" to false,
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                // summary + 4 originals + diff + analysis + native desc + native img + deriv desc + deriv img + boxed desc + boxed img + metadata
                assertEquals(14, result.content.size)
                val diffJson = Json.parseToJsonElement((result.content[5] as TextContent).text!!).jsonObject
                assertTrue(diffJson["total_changes"]!!.jsonPrimitive.int >= 1)
                val analysis = Json.parseToJsonElement((result.content[6] as TextContent).text!!).jsonObject
                assertEquals("success", analysis["verdict"]!!.jsonPrimitive.content)
                assertEquals("high", analysis["confidence"]!!.jsonPrimitive.content)
                val native = ImageIO.read(ByteArrayInputStream(java.util.Base64.getDecoder().decode((result.content[8] as ImageContent).data)))
                val derivative = ImageIO.read(ByteArrayInputStream(java.util.Base64.getDecoder().decode((result.content[10] as ImageContent).data)))
                assertNotNull(native)
                assertNotNull(derivative)
                assertEquals(native!!.width, derivative!!.width)
                assertTrue(derivative.height > native.height)
                val boxed = ImageIO.read(ByteArrayInputStream(java.util.Base64.getDecoder().decode((result.content[12] as ImageContent).data)))
                assertNotNull(boxed)
                assertEquals(native.width, boxed!!.width)
                assertEquals(native.height, boxed.height)
                val metadata = Json.parseToJsonElement((result.content[13] as TextContent).text!!).jsonObject
                assertEquals("success", metadata["verdict"]!!.jsonPrimitive.content)
                // Mocked editors expose no real text components: reported, not fatal.
                assertTrue(metadata["boxes"]!!.jsonArray.isEmpty())
                assertTrue(metadata["box_notes"]!!.jsonArray.isNotEmpty())
            }

            verify(exactly = 1) { requestEditor.setRequest(testReq) }
        }

        @Test
        fun `burp diff evidence toggles boxes and labels independently`() {
            val proxy = mockk<Proxy>()
            val baselineItem = mockk<ProxyHttpRequestResponse>()
            val testItem = mockk<ProxyHttpRequestResponse>()
            val baseReqT = mockk<HttpRequest>()
            val testReqT = mockk<HttpRequest>()
            val uiT = mockk<UserInterface>(relaxed = true)
            val requestEditorT = mockk<HttpRequestEditor>(relaxed = true)
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(baselineItem, testItem)
            every { baselineItem.request() } returns baseReqT
            every { baselineItem.response() } returns null
            every { testItem.request() } returns testReqT
            every { testItem.response() } returns null
            every { baseReqT.toString() } returns "POST /l HTTP/1.1\r\nHost: x\r\n\r\n{\"a\":\"1\"}"
            every { testReqT.toString() } returns "POST /l HTTP/1.1\r\nHost: x\r\n\r\n{\"a\":\"2\"}"
            every { api.userInterface() } returns uiT
            every { uiT.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditorT
            every { requestEditorT.uiComponent() } returns JPanel()
            val caretSlotT = slot<Int>()
            every { requestEditorT.setCaretPosition(capture(caretSlotT)) } just runs
            every { requestEditorT.caretPosition() } answers { caretSlotT.captured }

            runBlocking {
                val result = client.callTool(
                    "burp_diff_evidence",
                    mapOf(
                        "baseline_id" to "0",
                        "request_id" to "1",
                        "objective" to "value change is visible",
                        "capture_width" to 800,
                        "capture_height" to 600,
                        "redact_sensitive" to false,
                        "bounding_boxes" to false,
                        "box_labels" to false,
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                // No boxed desc/img blocks without bounding_boxes: 12 blocks.
                assertEquals(12, result.content.size)
                assertTrue((result.content[9] as TextContent).text!!.contains("caption only"))
                val metadata = Json.parseToJsonElement((result.content[11] as TextContent).text!!).jsonObject
                assertEquals(false, metadata["box_labels"]!!.jsonPrimitive.boolean)
            }
        }

        @Test
        fun `burp diff evidence with redaction keeps raw editors and notes overlays`() {
            val proxy = mockk<Proxy>()
            val baselineItem = mockk<ProxyHttpRequestResponse>()
            val testItem = mockk<ProxyHttpRequestResponse>()
            val baseReq = mockk<HttpRequest>()
            val testReq = mockk<HttpRequest>()
            val ui = mockk<UserInterface>(relaxed = true)
            val requestEditor = mockk<HttpRequestEditor>(relaxed = true)
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(baselineItem, testItem)
            every { baselineItem.request() } returns baseReq
            every { baselineItem.response() } returns null
            every { testItem.request() } returns testReq
            every { testItem.response() } returns null
            every { baseReq.toString() } returns "POST /l HTTP/1.1\r\nHost: x\r\n\r\n{\"password\":\"a\"}"
            every { testReq.toString() } returns "POST /l HTTP/1.1\r\nHost: x\r\n\r\n{\"password\":\"b\"}"
            every { api.userInterface() } returns ui
            every { ui.createHttpRequestEditor(EditorOptions.READ_ONLY) } returns requestEditor
            every { requestEditor.uiComponent() } returns JPanel()
            val caretSlot = slot<Int>()
            every { requestEditor.setCaretPosition(capture(caretSlot)) } just runs
            every { requestEditor.caretPosition() } answers { caretSlot.captured }

            runBlocking {
                val result = client.callTool(
                    "burp_diff_evidence",
                    mapOf(
                        "baseline_id" to "0",
                        "request_id" to "1",
                        "objective" to "password change is reflected",
                        "capture_width" to 800,
                        "capture_height" to 600,
                        "redact_sensitive" to true,
                    )
                )
                assertNotNull(result)
                assertFalse(result!!.isError == true)
                val metadata = Json.parseToJsonElement((result.content.last() as TextContent).text!!).jsonObject
                assertEquals(true, metadata["redaction_applied"]!!.jsonPrimitive.boolean)
                assertTrue(metadata["box_notes"]!!.jsonArray.isNotEmpty())
            }

            // Raw objects reach the editor: never rebuilt.
            verify(exactly = 1) { requestEditor.setRequest(testReq) }
        }

        @Test
        fun `burp diff evidence should reject identical pairs explicitly`() {
            val proxy = mockk<Proxy>()
            val item = mockk<ProxyHttpRequestResponse>()
            val request = mockk<HttpRequest>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(item)
            every { item.request() } returns request
            every { item.response() } returns null
            every { request.toString() } returns "GET / HTTP/1.1\r\nHost: x\r\n\r\n"

            runBlocking {
                val result = client.callTool(
                    "burp_diff_evidence",
                    mapOf(
                        "baseline_id" to "0",
                        "request_id" to "0",
                        "objective" to "anything",
                    )
                )
                assertNotNull(result)
                assertTrue(result!!.isError == true)
            }
        }

        @Test
        fun `get proxy history should paginate properly`() {            val proxy = mockk<Proxy>()
            val proxyHistory = listOf(
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>(),
                mockk<ProxyHttpRequestResponse>()
            )
            
            every { api.proxy() } returns proxy
            every { proxy.history() } returns proxyHistory
            
            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            
            every { proxyHistory[0].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item1 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 1 notes"
            )
            every { proxyHistory[1].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item2 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 2 notes"
            )
            every { proxyHistory[2].toSerializableForm() } returns HttpRequestResponse(
                request = "GET /item3 HTTP/1.1",
                response = "HTTP/1.1 200 OK",
                notes = "Item 3 notes"
            )
            
            runBlocking {
                val result1 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 0
                    )
                )
                
                delay(100)
                val text1 = result1.expectTextContent()
                assertTrue(text1.contains("GET /item1"))
                assertTrue(text1.contains("GET /item2"))
                assertFalse(text1.contains("GET /item3"))
                
                val result2 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 2
                    )
                )
                
                delay(100)
                val text2 = result2.expectTextContent()
                assertTrue(text2.contains("GET /item3"))
                
                val result3 = client.callTool(
                    "get_proxy_http_history", mapOf(
                        "count" to 2,
                        "offset" to 3
                    )
                )
                
                delay(100)
                assertEquals("Reached end of items", result3.expectTextContent())
            }
        }

        @Test
        fun `get proxy history should return valid size limited JSON`() {
            val proxy = mockk<Proxy>()
            val historyItem = mockk<ProxyHttpRequestResponse>()
            every { api.proxy() } returns proxy
            every { proxy.history() } returns listOf(historyItem)

            mockkStatic("net.portswigger.mcp.schema.SerializationKt")
            every { historyItem.toSerializableForm() } returns HttpRequestResponse(
                request = "GET / HTTP/1.1\r\nX-Long: ${"\\\"😀".repeat(2_000)}",
                response = "HTTP/1.1 200 OK\r\n\r\n${"😀".repeat(3_000)}",
                notes = "keep me"
            )

            runBlocking {
                val text = client.callTool(
                    "get_proxy_http_history", mapOf("count" to 1, "offset" to 0)
                ).expectTextContent()
                val item = Json.parseToJsonElement(text).jsonObject

                assertTrue(text.length <= 5_000)
                assertEquals(setOf("request", "response", "notes"), item.keys)
                assertTrue(item.getValue("request").jsonPrimitive.content.endsWith("... (truncated)"))
                assertTrue(item.getValue("response").jsonPrimitive.content.endsWith("... (truncated)"))
                assertEquals("keep me", item.getValue("notes").jsonPrimitive.content)
            }
        }
    }
    
    @Nested
    inner class CollaboratorToolsTests {
        private val collaborator = mockk<Collaborator>()
        private val collaboratorClient = mockk<CollaboratorClient>()
        private val collaboratorServer = mockk<CollaboratorServer>()

        @BeforeEach
        fun setupCollaborator() {
            mockkStatic(InteractionFilter::class)

            val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
            val version = mockk<burp.api.montoya.core.Version>()
            every { api.burpSuite() } returns burpSuite
            every { burpSuite.version() } returns version
            every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL
            every { burpSuite.taskExecutionEngine() } returns mockk(relaxed = true)
            every { burpSuite.exportProjectOptionsAsJson() } returns "{}"
            every { burpSuite.exportUserOptionsAsJson() } returns "{}"
            every { burpSuite.importProjectOptionsFromJson(any()) } just runs
            every { burpSuite.importUserOptionsFromJson(any()) } just runs

            every { api.collaborator() } returns collaborator
            every { collaborator.createClient() } returns collaboratorClient
            every { collaboratorClient.server() } returns collaboratorServer
            every { collaboratorServer.address() } returns "burpcollaborator.net"

            serverManager.stop {}
            serverStarted = false
            serverManager.start(config) { state ->
                if (state is ServerState.Running) serverStarted = true
            }

            runBlocking {
                var attempts = 0
                while (!serverStarted && attempts < 30) {
                    delay(100)
                    attempts++
                }
                if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")
                client.connectToServer("http://127.0.0.1:${testPort}")
            }
        }

        @AfterEach
        fun cleanupCollaborator() {
            unmockkStatic(InteractionFilter::class)
        }

        private fun mockInteraction(
            id: String,
            type: InteractionType,
            clientIp: String = "10.0.0.1",
            clientPort: Int = 54321,
            customData: String? = null,
            dnsDetails: DnsDetails? = null,
            httpDetails: HttpDetails? = null,
            smtpDetails: SmtpDetails? = null
        ): Interaction {
            val interactionId = mockk<InteractionId>()
            every { interactionId.toString() } returns id

            return mockk<Interaction>().also {
                every { it.id() } returns interactionId
                every { it.type() } returns type
                every { it.timeStamp() } returns ZonedDateTime.parse("2025-01-01T12:00:00Z")
                every { it.clientIp() } returns InetAddress.getByName(clientIp)
                every { it.clientPort() } returns clientPort
                every { it.customData() } returns Optional.ofNullable(customData)
                every { it.dnsDetails() } returns Optional.ofNullable(dnsDetails)
                every { it.httpDetails() } returns Optional.ofNullable(httpDetails)
                every { it.smtpDetails() } returns Optional.ofNullable(smtpDetails)
            }
        }

        @Test
        fun `generate payload should return payload and server info`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "abc123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "abc123"
            every { collaboratorClient.generatePayload() } returns payload

            runBlocking {
                val result = client.callTool("generate_collaborator_payload", emptyMap())
                delay(100)
                result.expectTextContent(
                    "Payload: abc123.burpcollaborator.net\n" +
                    "Payload ID: abc123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload() }
        }

        @Test
        fun `generate payload with custom data should pass custom data`() {
            val payload = mockk<CollaboratorPayload>()
            val payloadId = mockk<InteractionId>()
            every { payload.toString() } returns "custom123.burpcollaborator.net"
            every { payload.id() } returns payloadId
            every { payloadId.toString() } returns "custom123"
            every { collaboratorClient.generatePayload(any<String>()) } returns payload

            runBlocking {
                val result = client.callTool(
                    "generate_collaborator_payload", mapOf(
                        "customData" to "mydata"
                    )
                )
                delay(100)
                result.expectTextContent(
                    "Payload: custom123.burpcollaborator.net\n" +
                    "Payload ID: custom123\n" +
                    "Collaborator server: burpcollaborator.net"
                )
            }

            verify(exactly = 1) { collaboratorClient.generatePayload("mydata") }
        }

        @Test
        fun `get interactions should return dns interaction details`() {
            val dnsDetails = mockk<DnsDetails>().also {
                every { it.queryType() } returns DnsQueryType.A
            }
            val interaction = mockInteraction("int-001", InteractionType.DNS, dnsDetails = dnsDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"id\":\"int-001\""))
                assertTrue(text.contains("\"type\":\"DNS\""))
                assertTrue(text.contains("\"queryType\":\"A\""))
                assertTrue(text.contains("\"clientIp\":\"10.0.0.1\""))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return http interaction details`() {
            val mockRequest = mockk<burp.api.montoya.http.message.requests.HttpRequest>()
            every { mockRequest.toString() } returns "GET / HTTP/1.1"
            val mockResponse = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
            every { mockResponse.toString() } returns "HTTP/1.1 200 OK"
            val mockRequestResponse = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
            every { mockRequestResponse.request() } returns mockRequest
            every { mockRequestResponse.response() } returns mockResponse

            val httpDetails = mockk<HttpDetails>().also {
                every { it.protocol() } returns HttpProtocol.HTTP
                every { it.requestResponse() } returns mockRequestResponse
            }
            val interaction = mockInteraction("int-002", InteractionType.HTTP, httpDetails = httpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"HTTP\""))
                assertTrue(text.contains("\"protocol\":\"HTTP\""))
                assertTrue(text.contains("GET / HTTP/1.1"))
                assertTrue(text.contains("HTTP/1.1 200 OK"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions should return smtp interaction details`() {
            val smtpDetails = mockk<SmtpDetails>().also {
                every { it.protocol() } returns SmtpProtocol.SMTP
                every { it.conversation() } returns "EHLO test\r\n250 OK"
            }
            val interaction = mockInteraction("int-003", InteractionType.SMTP, smtpDetails = smtpDetails)
            every { collaboratorClient.getAllInteractions() } returns listOf(interaction)

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                val text = result.expectTextContent()
                assertTrue(text.contains("\"type\":\"SMTP\""))
                assertTrue(text.contains("\"protocol\":\"SMTP\""))
                assertTrue(text.contains("EHLO test"))
            }

            verify(exactly = 1) { collaboratorClient.getAllInteractions() }
        }

        @Test
        fun `get interactions with payloadId should use filter`() {
            val mockFilter = mockk<InteractionFilter>()
            every { InteractionFilter.interactionIdFilter("abc123") } returns mockFilter
            every { collaboratorClient.getInteractions(mockFilter) } returns emptyList()

            runBlocking {
                val result = client.callTool(
                    "get_collaborator_interactions", mapOf(
                        "payloadId" to "abc123"
                    )
                )
                delay(100)
                result.expectTextContent("No interactions detected")
            }

            verify(exactly = 1) { collaboratorClient.getInteractions(mockFilter) }
        }

        @Test
        fun `get interactions should return no interactions message when empty`() {
            every { collaboratorClient.getAllInteractions() } returns emptyList()

            runBlocking {
                val result = client.callTool("get_collaborator_interactions", emptyMap())
                delay(100)
                result.expectTextContent("No interactions detected")
            }
        }
    }

    @Test
    fun `tool name conversion should work properly`() {
        assertEquals("send_http1_request", "SendHttp1Request".toLowerSnakeCase())
        assertEquals("test_case_conversion", "TestCaseConversion".toLowerSnakeCase())
        assertEquals("multiple_upper_case_letters", "MultipleUpperCaseLetters".toLowerSnakeCase())
    }
    
    @Test
    fun `edition specific tools should only register in professional edition`() {
        val burpSuite = mockk<burp.api.montoya.burpsuite.BurpSuite>()
        val version = mockk<burp.api.montoya.core.Version>()
        
        every { api.burpSuite() } returns burpSuite
        every { burpSuite.version() } returns version
        
        every { version.edition() } returns BurpSuiteEdition.COMMUNITY_EDITION
        runBlocking {
            val tools = client.listTools()
            assertFalse(tools.any { it.name == "get_scanner_issues" })
            assertFalse(tools.any { it.name == "generate_collaborator_payload" })
            assertFalse(tools.any { it.name == "get_collaborator_interactions" })
        }

        every { version.edition() } returns BurpSuiteEdition.PROFESSIONAL

        serverManager.stop {}
        serverStarted = false
        serverManager.start(config) { state ->
            if (state is ServerState.Running) serverStarted = true
        }

        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 30) {
                delay(100)
                attempts++
            }
            if (!serverStarted) throw IllegalStateException("Server failed to start after timeout")

            client.connectToServer("http://127.0.0.1:${testPort}")

            val tools = client.listTools()
            assertTrue(tools.any { it.name == "get_scanner_issues" })
            assertTrue(tools.any { it.name == "generate_collaborator_payload" })
            assertTrue(tools.any { it.name == "get_collaborator_interactions" })
        }
    }
}
