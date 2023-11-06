package com.github.pfmiles.icapserver

import com.github.pfmiles.icapserver.impl.Constants
import io.github.rfc3507.server.Server
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.api.TestInstance.Lifecycle
import org.slf4j.LoggerFactory
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ThreadLocalRandom

@TestInstance(Lifecycle.PER_CLASS)
class TmpEchoTest {
    companion object {
        private val logger = LoggerFactory.getLogger(TmpEchoTest::class.java)

        private lateinit var server: Server
        private lateinit var client: TestIcapClient

        private val port = 50000 + ThreadLocalRandom.current().nextInt(5000)

        private const val data = "Hello World!"
        private val reqHeaders = """
                                     GET / HTTP/1.1
                                     Host: www.origin-server.com
                                     Accept: text/html, text/plain
                                     Accept-Encoding: compress
                                     Cookie: ff39fk3jur@4ii0e02i
                                     If-None-Match: "xyzzy", "r2d2xxxx"
                                     
                                     
                                 """.trimIndent().replace("\n", "\r\n")

        @JvmStatic
        @BeforeAll
        fun init() {
            System.setProperty(Constants.PORT_PROP_VAR, port.toString())
            server = Server()
            server.start()
            Thread.sleep(1000)

            client = TestIcapClient("127.0.0.1", port)
        }
    }

    @Test
    fun testNoBodyReqMod() {
        val noBodyReqMod = """
                               REQMOD icap://127.0.0.1/echo ICAP/1.0
                               Host: localhost
                               User-Agent: Icap-Client/1.0
                               Allow: 204
                               Encapsulated: req-hdr=0, null-body=${reqHeaders.length}
                               
                               
                           """.trimIndent().replace("\n", "\r\n") + reqHeaders
        logger.info(noBodyReqMod)
        logger.info(client.send(noBodyReqMod).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testNoBodyRespMod() {
        val noBodyRespMod = """
                                RESPMOD icap://127.0.0.1/echo ICAP/1.0
                                Host: localhost
                                User-Agent: Icap-Client/1.0
                                Allow: 204
                                Encapsulated: req-hdr=0, null-body=${reqHeaders.length}
                                
                                
                            """.trimIndent().replace("\n", "\r\n") + reqHeaders
        logger.info(noBodyRespMod)
        logger.info(client.send(noBodyRespMod).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testHasBodyReqMod() {
        val hasBodyReqMod = """
                                REQMOD icap://127.0.0.1/echo ICAP/1.0
                                Host: localhost
                                User-Agent: Icap-Client/1.0
                                Allow: 204
                                Encapsulated: req-hdr=0, req-body=0
                                
                                ${Integer.toHexString(data.length)}
                                $data
                                0
                                
                                
                            """.trimIndent().replace("\n", "\r\n")
        logger.info(hasBodyReqMod)
        logger.info(client.send(hasBodyReqMod).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testHasBodyRespMod() {
        val hasBodyRespMod = """
                                 RESPMOD icap://127.0.0.1:1344/echo ICAP/1.0
                                 Host: 127.0.0.1:1344
                                 Date: Sun, 05 Nov 2023 15:22:07 GMT
                                 Connection: close
                                 Encapsulated: req-hdr=0, res-hdr=98, res-body=474
                                 Allow: 204, trailers
                                 
                                 GET https://www.baidu.com/ HTTP/1.1
                                 Host: www.baidu.com
                                 User-Agent: curl/7.74.0
                                 Accept: */*
                                 
                                 HTTP/1.1 200 OK
                                 Accept-Ranges: bytes
                                 Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform
                                 Content-Length: 2443
                                 Content-Type: text/html
                                 Date: Sun, 05 Nov 2023 15:22:07 GMT
                                 ETag: "588603e2-98b"
                                 Last-Modified: Mon, 23 Jan 2017 13:23:46 GMT
                                 Pragma: no-cache
                                 Server: bfe/1.0.8.18
                                 Set-Cookie: BDORZ=27315; max-age=86400; domain=.baidu.com; path=/
                                 
                                 ${Integer.toHexString(data.length)}
                                 $data
                                 0
                                 
                                 
                             """.trimIndent().replace("\n", "\r\n")
        logger.info(hasBodyRespMod.replace("\r", "\\r").replace("\n", "\\n\n"))
        logger.info(client.send(hasBodyRespMod).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testHasBodyReqModIeof() {
        val hasBodyReqModIeof = """
                                    REQMOD icap://127.0.0.1/echo ICAP/1.0
                                    Host: localhost
                                    User-Agent: Icap-Client/1.0
                                    Allow: 204
                                    Encapsulated: req-hdr=0, req-body=0
                                    
                                    ${Integer.toHexString(data.length)}
                                    $data
                                    0; ieof
                                    
                                    
                                """.trimIndent().replace("\n", "\r\n")
        logger.info(hasBodyReqModIeof)
        logger.info(client.send(hasBodyReqModIeof).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testHasBodyRespModIeof() {
        val hasBodyRespModIeof = """
                                     RESPMOD icap://127.0.0.1/echo ICAP/1.0
                                     Host: localhost
                                     User-Agent: Icap-Client/1.0
                                     Allow: 204
                                     Encapsulated: req-hdr=0, res-body=0
                                     
                                     ${Integer.toHexString(data.length)}
                                     $data
                                     0; ieof
                                     
                                     
                                 """.trimIndent().replace("\n", "\r\n")
        logger.info(hasBodyRespModIeof)
        logger.info(client.send(hasBodyRespModIeof).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testConnectIssue() {
        val connectReqMod = """
                                REQMOD icap://127.0.0.1:1344/echo ICAP/1.0
                                Host: 127.0.0.1:1344
                                Date: Fri, 03 Nov 2023 13:21:31 GMT
                                Connection: close
                                Encapsulated: req-hdr=0, null-body=88
                                Allow: 204, trailers
                                
                                CONNECT www.baidu.com:443 HTTP/1.1
                                Host: www.baidu.com:443
                                User-Agent: curl/7.74.0
                                
                                
                            """.trimIndent().replace("\n", "\r\n")
        logger.info(connectReqMod)
        logger.info(client.send(connectReqMod).replace("\r", "\\r").replace("\n", "\\n\n"))
    }

    @Test
    fun testLength() {
        val df = SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z", Locale.US).apply {
            this.timeZone = TimeZone.getTimeZone("GMT")
        }
        val ctt = """
                      ICAP/1.0 204 No Content
                      Date: ${df.format(Date())}
                      Server: ICAP-Server/1.0
                      ISTag:"3fbb2a4851054d7d964fa3a1762d809a"
                      Connection: close
                      Encapsulated: req-hdr=0, null-body=88

                      CONNECT www.baidu.com:443 HTTP/1.1
                      Host: www.baidu.com:443
                      User-Agent: curl/7.74.0
                      
                      
                  """.trimIndent().replace("\n", "\r\n").replace("\r", "\\r").replace("\n", "\\n\n")
        println(ctt)
    }

}