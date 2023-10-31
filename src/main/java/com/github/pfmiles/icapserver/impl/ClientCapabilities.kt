package com.github.pfmiles.icapserver.impl

/**
 * Client's capabilities learnt during an icap request handling progress.
 *
 * @author pf-miles
 */
internal data class ClientCapabilities(
    /**
     * If the client accepts '204 No Content' response
     */
    val noContent204: Boolean = false)
