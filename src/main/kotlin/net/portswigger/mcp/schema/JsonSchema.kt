package net.portswigger.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties
import kotlin.reflect.full.primaryConstructor

fun getJsonSchemaForProperty(kType: kotlin.reflect.KType, seen: Set<KClass<*>> = emptySet()): JsonElement {
    return when (kType.classifier) {
        String::class ->
            JsonObject(mapOf("type" to JsonPrimitive("string")))

        Int::class, Long::class ->
            JsonObject(mapOf("type" to JsonPrimitive("integer")))

        Float::class, Double::class ->
            JsonObject(mapOf("type" to JsonPrimitive("number")))

        Boolean::class ->
            JsonObject(mapOf("type" to JsonPrimitive("boolean")))

        List::class, Array::class -> {
            val argType = kType.arguments.firstOrNull()?.type
            val itemsSchema = when {
                argType != null -> getJsonSchemaForProperty(argType, seen)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to itemsSchema))
        }

        Map::class -> {
            val valueType = kType.arguments.getOrNull(1)?.type
            val valueSchema = when {
                valueType != null -> getJsonSchemaForProperty(valueType, seen)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("object"), "additionalProperties" to valueSchema))
        }

        else -> {
            val classifier = kType.classifier as? KClass<*>
                ?: return JsonObject(mapOf("type" to JsonPrimitive("object")))
            if (classifier.java.isEnum) {
                JsonObject(
                    mapOf(
                        "type" to JsonPrimitive("string"),
                        "enum" to kotlinx.serialization.json.JsonArray(
                            classifier.java.enumConstants.map { JsonPrimitive((it as Enum<*>).name) }
                        )
                    )
                )
            } else if (classifier in seen) {
                JsonObject(mapOf("type" to JsonPrimitive("object")))
            } else {
                schemaForClass(classifier, seen + classifier)
            }
        }
    }
}

private fun schemaForClass(type: KClass<*>, seen: Set<KClass<*>>): JsonObject {
    val constructorParameters = type.primaryConstructor?.parameters?.associateBy { it.name }.orEmpty()
    val properties = type.memberProperties.associate { property ->
        property.name to getJsonSchemaForProperty(property.returnType, seen)
    }
    val required = type.memberProperties.filter { property ->
        val parameter = constructorParameters[property.name]
        !property.returnType.isMarkedNullable && parameter?.isOptional != true
    }.map { it.name }
    return JsonObject(
        buildMap {
            put("type", JsonPrimitive("object"))
            put("properties", JsonObject(properties))
            if (required.isNotEmpty()) {
                put("required", kotlinx.serialization.json.JsonArray(required.map(::JsonPrimitive)))
            }
        }
    )
}

fun KClass<*>.asInputSchema(): ToolSchema {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()
    val constructorParameters = primaryConstructor?.parameters?.associateBy { it.name }.orEmpty()

    for (prop in memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType)

        if (!prop.returnType.isMarkedNullable && constructorParameters[prop.name]?.isOptional != true) {
            required.add(prop.name)
        }
    }

    return ToolSchema(
        properties = JsonObject(properties),
        required = required
    )
}
