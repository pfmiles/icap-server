package com.github.pfmiles.icapserver

/**
 * Constants
 *
 * @author pf-miles
 */
object Constants {
    /**
     * icap server port specified in system environment, has the highest priority
     */
    const val PORT_ENV_VAR = "ICAP_SERVER_PORT"

    /**
     * icap server port specified in vm parameters, has lower priority than 'PORT_ENV_VAR'
     */
    const val PORT_PROP_VAR = "icap.server.port"

    /**
     * the default server port of icap server
     */
    const val DFT_PORT = "1344"

    /**
     * the size of the handling thread pool of the icap server
     */
    val workerPoolSize = Runtime.getRuntime().availableProcessors() * 100
}