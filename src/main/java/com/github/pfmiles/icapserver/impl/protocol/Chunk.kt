package com.github.pfmiles.icapserver.impl.protocol

import com.github.pfmiles.icapserver.impl.Constants.CRLF
import java.nio.charset.StandardCharsets

/**
 * Encapsulation of a (relatively) small 'chunk' of data defined in the chunked-transfer data format.
 *
 * @author pf-miles
 */
internal open class Chunk(val content: ByteArray) {

    companion object {
        /**
         * The last chunk of a chunked-transfer session.
         */
        val FINAL_CHUNK = object : Chunk(ByteArray(0)) {
            override fun toByteArray() = "0$CRLF$CRLF".toByteArray(StandardCharsets.UTF_8)
        }

        /**
         * The ieof final chunk in preview mode.
         * Defined in rfc3507: https://datatracker.ietf.org/doc/html/rfc3507#section-4.5
         */
        val IEOF_CHUNK = object : Chunk(ByteArray(0)) {
            override fun toByteArray() = "0; ieof$CRLF$CRLF".toByteArray(StandardCharsets.UTF_8)
        }
    }

    open fun toByteArray() = "${Integer.toHexString(content.size)}${CRLF}".toByteArray(StandardCharsets.UTF_8) + content + CRLF.toByteArray(StandardCharsets.UTF_8)

    fun size() = this.content.size

}
