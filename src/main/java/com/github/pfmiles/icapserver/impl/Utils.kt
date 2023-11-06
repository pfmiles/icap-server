package com.github.pfmiles.icapserver.impl

import com.github.pfmiles.icapserver.impl.protocol.Chunk
import org.slf4j.LoggerFactory
import java.io.InputStream
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.util.*

/**
 * internal utilities
 *
 * @author pf-miles
 */
internal object Utils {
    private val logger = LoggerFactory.getLogger(Utils::class.java)

    fun optsInOrDefault(envKey: String, vmOpsKey: String, dftVal: String) = System.getenv(envKey) ?: System.getProperty(vmOpsKey) ?: dftVal

    fun resolveLocalAddresses(): Set<InetAddress> {
        var ns: Enumeration<NetworkInterface>? = null
        try {
            ns = NetworkInterface.getNetworkInterfaces()
        } catch (e: SocketException) {
            // ignored...
        }
        val addrs: MutableSet<InetAddress> = mutableSetOf()
        while (ns != null && ns.hasMoreElements()) {
            val n = ns.nextElement()
            val addr = n.inetAddresses
            while (addr.hasMoreElements()) {
                val i = addr.nextElement()
                if (!i.isLoopbackAddress && !i.isLinkLocalAddress && !i.isMulticastAddress && !isSpecialIp(i.hostAddress)) addrs.add(i)
            }
        }
        return addrs
    }

    fun resolveLocalIps(): Set<String> {
        val addrs = resolveLocalAddresses()
        val ret: MutableSet<String> = mutableSetOf()
        for (addr in addrs) ret.add(addr.hostAddress)
        return ret
    }

    private fun isSpecialIp(ip: String): Boolean {
        if (ip.contains(":")) return true
        if (ip.startsWith("127.")) return true
        if (ip.startsWith("169.254.")) return true
        return if (ip == "255.255.255.255") true else false
    }

    fun randomUUID32Chars() = UUID.randomUUID().toString().replace("-", "").uppercase()

    // to chunked encoding, keeping the stream-processing style
    fun chunkenize(ins: InputStream, chunkSize: Int = 4096): Iterator<Chunk> {
        val buf = ByteArray(chunkSize)
        var finalChunkReturned = false
        var read = ins.read(buf)
        return object : Iterator<Chunk> {
            override fun hasNext(): Boolean = read != -1 || !finalChunkReturned

            override fun next(): Chunk = if (read != -1) {
                Chunk(buf.sliceArray(0 until read)).also { read = ins.read(buf) }
            } else if (!finalChunkReturned) {
                Chunk.FINAL_CHUNK.also { finalChunkReturned = true }
            } else {
                throw NoSuchElementException("No more element.")
            }

        }
    }
}