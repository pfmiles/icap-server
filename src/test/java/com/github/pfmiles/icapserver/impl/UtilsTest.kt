package com.github.pfmiles.icapserver.impl

import com.github.pfmiles.icapserver.impl.protocol.Chunk
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import java.nio.charset.StandardCharsets
import kotlin.math.ceil

@TestInstance(Lifecycle.PER_CLASS)
class UtilsTest {
    @Test
    fun testChunkenize() {
        val data = """
                       The ICAP "OPTIONS" method is used by the ICAP client to retrieve
                       configuration information from the ICAP server.  In this method, the
                       ICAP client sends a request addressed to a specific ICAP resource and
                       receives back a response with options that are specific to the
                       service named by the URI.  All OPTIONS requests MAY also return
                       options that are global to the server (i.e., apply to all services).
                   """.trimIndent()
        val chunks = Utils.chunkenize(data.byteInputStream(StandardCharsets.UTF_8), 16)
        val allChunks = mutableListOf<Chunk>()
        chunks.forEach(allChunks::add)

        // test resulting chunks num
        Assertions.assertTrue(allChunks.size == ceil(data.toByteArray(StandardCharsets.UTF_8).size / 16.toDouble()).toInt() + 1)

        // chunked content size be held
        Assertions.assertEquals(data.toByteArray(StandardCharsets.UTF_8).size, allChunks.fold(0) { cnt, chunk -> cnt + chunk.size() })

        // chunked content be held
        Assertions.assertEquals(data, allChunks.fold(ByteArray(0)) { bs, chunk -> bs + chunk.content }.toString(StandardCharsets.UTF_8))

        println(allChunks.fold(ByteArray(0)) { bs, chunk -> bs + chunk.toByteArray() }.toString(StandardCharsets.UTF_8).replace("\r", "\\r").replace("\n", "\\n\n"))
    }
}