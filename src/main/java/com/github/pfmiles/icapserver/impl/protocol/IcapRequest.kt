package com.github.pfmiles.icapserver.impl.protocol

import com.github.pfmiles.icapserver.IcapMethod

/**
 * The encapsulation and parsing context of an incoming icap request.
 *
 * @author pf-miles
 */
internal class IcapRequest {

    lateinit var requestLine: String

    lateinit var method: IcapMethod

    // origin icap request headers string, excludes the ending CRLF * 2
    lateinit var icapReqHeadersStr: String

    lateinit var icapReqHeadersMap: Map<String, String>

    var encapsulatedHeader: EncapsulatedHeader? = null

    /**
     * TODO preview, 204(inside/outside), 206, trailers capable to be implemented
     */

    // the encapsulated http message headers, if any

    // origin http request headers string, if any, including the terminating CRLF * 2
    var httpReqHeadersStr: String? = null

    var httpReqHeadersMap: Map<String, String>? = null

    // origin http response headers string, if any, including the terminating CRLF * 2
    var httpRespHeadersStr: String? = null

    var httpRespHeadersMap: Map<String, String>? = null

    // the encapsulated http message body chunks, if any, including the final chunk/ieof chunk
    var httpBodyChunks: Iterator<Chunk>? = null
}