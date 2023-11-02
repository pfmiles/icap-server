package com.github.pfmiles.icapserver.impl.protocol

/**
 * Client's capabilities learnt during an icap request handling progress.
 *
 * @author pf-miles
 */
internal data class ClientCapabilities(
    /**
     * If the client accepts '204 No Content' response
     */
    val noContent204: Boolean = false,
    /**
     * If the client accepts some headers sent after last chunk —— trailers
     */
    val trailers: Boolean = false)
