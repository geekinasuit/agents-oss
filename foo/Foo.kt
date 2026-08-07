package com.geekinasuit.agency.foo

import org.json.JSONObject

/**
 * Probe library exercising the module skeleton end to end: the Kotlin toolchain, a Maven
 * dependency, and consumption from a dependent Bazel module. Removed when the first real
 * package lands.
 */
object Foo {
    /** Renders [pairs] as a JSON object string. */
    fun toJson(pairs: Map<String, String>): String {
        val obj = JSONObject()
        pairs.forEach { (key, value) -> obj.put(key, value) }
        return obj.toString()
    }
}
