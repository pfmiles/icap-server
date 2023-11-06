package com.github.pfmiles.icapserver.impl

import org.slf4j.LoggerFactory
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets

/**
 * just for test, print out what have been written.
 */
internal class TeeOutputStream(val dest: OutputStream) : OutputStream() {
    companion object {
        private val logger = LoggerFactory.getLogger(TeeOutputStream::class.java)
    }

    private val backup = ByteArrayOutputStream()

    override fun write(b: Int) {
        dest.write(b)
        backup.write(b)
    }

    override fun flush() {
        dest.flush();
        logger.info("Stream wrote out:\n${backup.toString(StandardCharsets.UTF_8.name()).replace("\r", "\\r").replace("\n", "\\n\n")}")
    }

    override fun close() {
        this.flush()
        dest.close();
        super.close()
    }
}