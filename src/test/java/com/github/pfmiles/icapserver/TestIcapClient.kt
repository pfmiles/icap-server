package com.github.pfmiles.icapserver

import org.apache.commons.io.IOUtils
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 * @property ip the ip address of the target icap server
 * @property port the port of the target icap server
 */
class TestIcapClient(val ip: String, val port: Int) {
    companion object {
        val logger = LoggerFactory.getLogger(TestIcapClient::class.java)
    }

    val inetSocketAddress = InetSocketAddress(InetAddress.getByName(ip), port)

    /**
     * send icap request message and return the response
     *
     * TODO currently no preview functionality supported
     */
    fun send(message: String): String {
        // TODO currently no keep-alive supported
        createSocket().use {
            val ous = it.getOutputStream()
            val ins = it.getInputStream()

            // write-out the request
            ous.write(message.toByteArray(StandardCharsets.UTF_8))
            ous.flush()

            // read-in the icap server response
            return IOUtils.toString(ins, StandardCharsets.UTF_8)
        }
    }

    private fun createSocket(): Socket {
        val socket = Socket()
        socket.soTimeout = 3600000
        socket.connect(inetSocketAddress, 5000)
        return socket
    }
}