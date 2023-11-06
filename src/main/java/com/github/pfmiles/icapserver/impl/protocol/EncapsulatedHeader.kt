package com.github.pfmiles.icapserver.impl.protocol

/**
 * The encapsulated header, defined in rfc3507: https://datatracker.ietf.org/doc/html/rfc3507#section-4.4.1
 *
 * @property reqHdr the offset in icap message body of the encapsulated http request headers
 * @property resHdr the offset in icap message body of the encapsulated http response headers
 * @property reqBody the offset in icap message body of the encapsulated http request body
 * @property resBody the offset in icap message body of the encapsulated http response body
 * @property optBody the offset in icap message body of the OPTIONS response body, defined in: https://datatracker.ietf.org/doc/html/rfc3507#section-4.10.2
 * @property nullBody the offset in icap message body when there is no encapsulated message body at all, used to indicate previews header data's size
 *
 * Some validation restrictions according to rfc3507:
 * 1) there can only be zero or one 'body' value in this header
 * 2) RESPMOD request can have both reqHdr & resHdr, but its corresponding icap response can only have resHdr
 * 3) the icap message data writing order must be the same as the offset values' appearing order in the 'Encapsulated' header
 * 4) if 'opt-body' presents, there must be a corresponding 'Opt-body-type' header in the icap response
 *
 * @author pf-miles
 */
internal data class EncapsulatedHeader(val reqHdr: Int, val resHdr: Int, val reqBody: Int, val resBody: Int, val optBody: Int, val nullBody: Int)
