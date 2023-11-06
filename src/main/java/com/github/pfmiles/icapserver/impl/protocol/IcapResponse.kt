package com.github.pfmiles.icapserver.impl.protocol

import java.util.*

/**
 * The encapsulation and rendering context of an out-going icap response.
 *
 * @author pf-miles
 */
internal class IcapResponse(val icapRequest: IcapRequest) {

    lateinit var statusLine: String

    // the icap response headers
    val icapRespHeadersMap: SortedMap<String, String> = sortedMapOf()

    // http req header and http resp header can only have one

    // the out-going encapsulated http request headers string, if any, including the terminating CRLF * 2
    var httpReqHeadersStr: String? = null

    // the out-going encapsulated http response headers string, if any, including the terminating CRLF * 2
    var httpRespHeadersStr: String? = null

    // the out-going http message body chunks, if any, including the final chunk, these chunks will be written out to client as the iteration order
    var httpBodyChunks: Iterator<Chunk>? = null
}