package com.github.pfmiles.icapserver.impl.protocol

import com.github.pfmiles.icapserver.IcapMethod

/**
 * The standard methods of ICAP protocol.
 *
 * @author pf-miles
 */
internal enum class IcapStdMethod : IcapMethod {
    OPTIONS, REQMOD, RESPMOD
}