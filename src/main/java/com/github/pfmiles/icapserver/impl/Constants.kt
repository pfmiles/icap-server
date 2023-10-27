package com.github.pfmiles.icapserver.impl

/**
 * Constants
 *
 * @author pf-miles
 */
internal object Constants {

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
     * limit the max count of threads the worker pool can create
     * TODO may improve with a new nio-fiber-busyThreads processing model
     */
    val WORKER_POOL_SIZE = Runtime.getRuntime().availableProcessors() * 100

    /**
     * the local ip address, picking the randomly first one, special ips like '127.0.0.1' as such are bypassed
     */
    val LOCAL_IP = Utils.resolveLocalIps().first()

    /**
     * scanning base package of all standard modules
     */
    const val STD_MODULE_PKG = "com.github.pfmiles.icapserver.standardmodules"

    /**
     * server name definition key in system env, used in 'Service' response header
     */
    const val SVR_NAME_PROPS_VAR = "ICAP_SERVER_NAME"

    /**
     * server name def key in vm options, used in 'Service' response header
     */
    const val SVR_NAME_ENV_VAR = "icap.server.name"

    /**
     * the default value of OPTIONS response's 'Service' header
     */
    const val DFT_SVC_VAL = "ICAP-Server/1.0"
}