package net.portswigger.mcp.schema

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.portswigger.mcp.tools.ScreenshotProxyHttpHistory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsonSchemaNestedTest {
    @Test
    fun `nested annotation schema is exposed and default fields are optional`() {
        val schema = ScreenshotProxyHttpHistory::class.asInputSchema()
        val properties = requireNotNull(schema.properties)
        val annotations = properties.getValue("annotations").jsonObject
        val itemProperties = annotations.getValue("items").jsonObject
            .getValue("properties").jsonObject

        assertEquals("string", itemProperties.getValue("match").jsonObject.getValue("type").jsonPrimitive.content)
        assertEquals("string", itemProperties.getValue("label").jsonObject.getValue("type").jsonPrimitive.content)
        val required = requireNotNull(schema.required)
        assertTrue("offset" in required)
        assertFalse("redactSecrets" in required)
        assertFalse("annotations" in required)
        val nestedRequired = annotations.getValue("items").jsonObject.getValue("required").jsonArray
            .map { it.jsonPrimitive.content }
        assertEquals(setOf("match", "label"), nestedRequired.toSet())
    }
}
