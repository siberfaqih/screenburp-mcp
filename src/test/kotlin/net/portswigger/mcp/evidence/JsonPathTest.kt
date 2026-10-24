package net.portswigger.mcp.evidence

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JsonPathTest {
    private fun obj() = Json.parseToJsonElement(
        """{"user":{"name":"ada","roles":["admin","user"]},"count":3}"""
    )

    @Test
    fun `resolves children indexes and wildcards`() {
        val root = obj()
        assertEquals("ada", JsonPath.evaluate(root, "$.user.name").single().element.toString().trim('"'))
        assertEquals("$.user.roles[0]", JsonPath.evaluate(root, "$.user.roles[0]").single().path)
        assertEquals(2, JsonPath.evaluate(root, "$.user.roles[*]").size)
        assertEquals(2, JsonPath.evaluate(root, "$.*").size)
        assertEquals("ada", JsonPath.evaluate(root, "$['user']['name']").single().element.toString().trim('"'))
        assertEquals("admin", JsonPath.evaluate(root, "$.user.roles[-2]").single().element.toString().trim('"'))
    }

    @Test
    fun `supports recursive descent`() {
        val root = obj()
        val names = JsonPath.evaluate(root, "$..name")
        assertEquals(1, names.size)
        assertEquals("$.user.name", names.single().path)
        assertTrue(JsonPath.evaluate(root, "$..missing").isEmpty())
    }

    @Test
    fun `rejects unsupported syntax explicitly`() {
        val root = JsonObject(emptyMap())
        assertFailsWith<IllegalArgumentException> { JsonPath.evaluate(root, "user.name") }
        assertFailsWith<IllegalArgumentException> { JsonPath.evaluate(root, "$.a[1,2]") }
        assertFailsWith<IllegalArgumentException> { JsonPath.evaluate(root, "$.a[?(@.b)]") }
        assertFailsWith<IllegalArgumentException> { JsonPath.evaluate(root, "$.a[") }
    }
}
