package com.geekinasuit.agency.foo

import org.junit.Assert.assertEquals
import org.junit.Test

class FooTest {
    @Test
    fun rendersPairsAsJson() {
        assertEquals("""{"a":"1"}""", Foo.toJson(mapOf("a" to "1")))
    }

    @Test
    fun rendersEmptyMapAsEmptyObject() {
        assertEquals("{}", Foo.toJson(emptyMap()))
    }
}
