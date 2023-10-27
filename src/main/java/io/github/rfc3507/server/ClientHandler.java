package io.github.rfc3507.server;

import com.github.pfmiles.icapserver.impl.Constants;
import com.github.pfmiles.icapserver.impl.Utils;
import io.github.rfc3507.av.clamav.ClamAVCore;
import io.github.rfc3507.av.clamav.ClamAVResponse;
import io.github.rfc3507.av.windowsdefender.WindowsDefenderAntivirus;
import io.github.rfc3507.av.windowsdefender.WindowsDefenderResponse;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClientHandler implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ClientHandler.class);

    private static final String serverName = Utils.INSTANCE.optsInOrDefault(Constants.SVR_NAME_ENV_VAR, Constants.SVR_NAME_PROPS_VAR, Constants.DFT_SVC_VAL);
    private static final byte[] SERVICE_RESP_HEADER = ("Service: " + serverName + "\r\n").getBytes(StandardCharsets.US_ASCII);
    private static final String SERVER_HEADER = "Server: " + serverName + "\r\n";
    private static final String VIA_HEADER = "Via: " + serverName + "\r\n";

    private static final String localIp = Constants.INSTANCE.getLOCAL_IP();

    // TODO methods may extend in future
    private static final String OPTIONS = "OPTIONS";
    private static final String REQMOD = "REQMOD";
    private static final String RESPMOD = "RESPMOD";

    private final Socket socket;

    private InputStream in;
    private OutputStream out;

    private String methodInProgress = null;
    private String serviceInProgress = null;

    private String encapsulatedHeader = null;
    private String previewHeader = null;

    private ByteArrayOutputStream httpRequestHeaders = null;
    private ByteArrayOutputStream httpRequestBody = null;
    private ByteArrayOutputStream httpResponseHeaders = null;
    private ByteArrayOutputStream httpResponseBody = null;

    public ClientHandler(Socket c) {
        this.socket = c;
    }

    @Override
    public void run() {
        try {
            in = socket.getInputStream();
            out = socket.getOutputStream();
            handle();
            logger.info("Client request completed.");
        } catch (IOException e) {
            logger.error("IO Exception when processing client request, processing terminated.", e);
        } finally {
            IOUtils.closeQuietly(out, ioe -> logger.warn("Closing socket output stream error, ignored...", ioe));
            IOUtils.closeQuietly(in, ioe -> logger.warn("Closing socket input stream error, ignored...", ioe));
            IOUtils.closeQuietly(socket, ioe -> logger.warn("Closing client socket error, ignored...", ioe));
        }
    }

    private void handle() throws IOException {

        while (true) { // label: handleStart

            httpRequestHeaders = new ByteArrayOutputStream();
            httpRequestBody = new ByteArrayOutputStream();
            httpResponseHeaders = new ByteArrayOutputStream();
            httpResponseBody = new ByteArrayOutputStream();

            methodInProgress = null;

            try {
                handleIcapRequestHeaders();
                if (methodInProgress != null) {
                    handleEncapsulatedMessage();
                }
                out.flush();
            } catch (Exception e) {
                logger.error("Error when processing icap request, process for this request terminated.", e);
                sendServerError(e.getMessage());
            }

            if (OPTIONS.equals(methodInProgress)) { // TODO what if 'too many OPTIONS' attack?
                continue; // goto: handleStart
            }
            break;
        }

    }

    // processing icap-request related headers
    private void handleIcapRequestHeaders() throws Exception {

        ByteArrayOutputStream cache = new ByteArrayOutputStream();

        // TODO: to detect the first CRLF, this logic requires a more elegant way
        int reader = -1;
        while ((reader = in.read()) != -1) {

            cache.write(reader);

            byte[] memory = cache.toByteArray();
            // CRLF encountered, analyze icap headers
            if (memory.length >= 4) {
                if (memory[memory.length - 4] == '\r'
                        && memory[memory.length - 3] == '\n'
                        && memory[memory.length - 2] == '\r'
                        && memory[memory.length - 1] == '\n') {

                    analyseIcapRequestHeader(memory);
                    break;

                }
            }

        }

    }

    // icap request headers processed, continue to process further REQMOD/RESPMOD request body
    private void handleEncapsulatedMessage() throws Exception {

        extractEncapsulatedPayloads();

        // OPTIONS is already handled in 'startHandleIcapRequest', so REQMOD/RESPMOD only here
        if (REQMOD.equals(methodInProgress)) {
            continueRequestModification();
        } else if (RESPMOD.equals(methodInProgress)) {
            continueResponseModification();
        }

    }

    // parse the encapsulated http messages
    private void extractEncapsulatedPayloads() throws Exception {

        // the encapsulated http headers' size
        int httpRequestHeaderSize = 0;
        int httpResponseHeaderSize = 0;

        String lastOffsetLabel = "";

        int lastOffsetValue = 0;

        String[] encapsulatedValues = encapsulatedHeader.split(",");

        // compute encapsulated http headers' size in 'Encapsulated' header value, for example: 'req-hdr=0, res-hdr=822, res-body=1655'
        for (String offset : encapsulatedValues) {

            String[] offsetParser = offset.split("=");

            String offsetLabel = offsetParser[0].trim();

            int offsetValue = Integer.parseInt(offsetParser[1].trim());

            switch (lastOffsetLabel) {

                case "req-hdr":
                    httpRequestHeaderSize = (offsetValue - lastOffsetValue);
                    break;

                case "res-hdr":
                    httpResponseHeaderSize = (offsetValue - lastOffsetValue);
                    break;

            }

            lastOffsetLabel = offsetLabel;
            lastOffsetValue = offsetValue;

        }

        byte[] parseContent;

        if (httpRequestHeaderSize > 0) {
            parseContent = new byte[httpRequestHeaderSize];
            IOUtils.readFully(in, parseContent);
            httpRequestHeaders.write(parseContent);
        }

        if (httpResponseHeaderSize > 0) {
            parseContent = new byte[httpResponseHeaderSize];
            IOUtils.readFully(in, parseContent);
            httpResponseHeaders.write(parseContent);
        }

        if ("req-body".equals(lastOffsetLabel)) {
            readBody(httpRequestBody);
        }

        if ("res-body".equals(lastOffsetLabel)) {
            readBody(httpResponseBody);
        }

    }

    private void readBody(OutputStream bodyData) throws Exception {

        boolean terminateWhilePreview = false;

        if (previewHeader != null) {
            /*
             * Read preview payload
             */
            int expPreviewLength = Integer.parseInt(previewHeader);
            // actual preview data sent by client may be less than it claimed in the 'Preview' header
            terminateWhilePreview = extractBody(bodyData, expPreviewLength);
            if (!terminateWhilePreview) {
                sendContinue();
            }
        }

        if (!terminateWhilePreview) {
            /*
             * Read remaining body payload
             */
            extractBody(bodyData, -1);
        }

    }

    // @return whether the preview data is all the message body about
    // TODO preview feature is not implemented
    private boolean extractBody(OutputStream bodyData, int previewSize) throws Exception {

        ByteArrayOutputStream backupDebug = new ByteArrayOutputStream();

        // the hex representation of chunk size
        StringBuilder chunkSizeHexStr = new StringBuilder();

        int[] mark = new int[2];
        Arrays.fill(mark, -1);

        StringBuilder control = new StringBuilder();

        while (true) {

            int nextChar = in.read();
            shiftLeftByOne(mark);
            mark[1] = nextChar;

            backupDebug.write(nextChar);

            control.append((char) nextChar);

            // try reading preview-specific 'ieof' chunk start
            if (nextChar == ';') {
                continue;
            }

            if (nextChar == ' ' || nextChar == 'i') {
                continue;
            }

            if (nextChar == 'e') {
                if (control.toString().equals("0; ie")) {
                    continue;
                }
            }

            if (nextChar == 'f') {
                if (control.toString().equals("0; ieof")) {
                    continue;
                }
            }
            // try reading preview-specific 'ieof' chunk end

            if (nextChar == '\r') {
                continue;
            }

            // when a CRLF encountered
            if (mark[0] == '\r' && mark[1] == '\n') {

                if (control.toString().equals("0; ieof\r\n\r\n")) {
                    return true;
                }

                if (control.toString().startsWith("0; ieof")) {
                    continue;
                }

                if (chunkSizeHexStr.length() == 0) {
                    return false;
                }

                // read the data chunk according to the chunk size
                int amountToRead = Integer.parseInt(chunkSizeHexStr.toString(), 16);
                if (amountToRead > 0) {
                    byte[] cache = new byte[amountToRead];
                    IOUtils.readFully(in, cache);
                    bodyData.write(cache);
                    backupDebug.write(cache);
                }

                // consume the CRLF after: a chunk of data/last empty chunk
                int cr = -1, lf = -1;
                cr = in.read();
                lf = in.read();
                backupDebug.write(cr);
                backupDebug.write(lf);

                if (cr != '\r' || lf != '\n') {
                    throw new Exception("Error reading end of chunk");
                }

                if (amountToRead > 0) {
                    // after previous chunk data read, the control string reset
                    control = new StringBuilder();
                } else {
                    // append the last CRLF after a last empty chunk
                    control.append((char) cr);
                    control.append((char) lf);
                }

                if (control.toString().equals("0\r\n\r\n")) {
                    return false;
                }

                chunkSizeHexStr.setLength(0);

                continue;

            }

            chunkSizeHexStr.append((char) nextChar);

        }

    }

    private void analyseIcapRequestHeader(byte[] memory) throws Exception {

        String data = new String(memory);

        String[] entries = data.split("\\r\\n");

        if (entries.length == 0) {
            sendBadRequest("Invalid ICAP Request");
            return;
        }

        String methodLine = entries[0];
        String methodLineUpper = methodLine.toUpperCase();

        // TODO method would be extensible
        if (!methodLineUpper.startsWith(OPTIONS)
                && !methodLineUpper.startsWith(REQMOD)
                && !methodLineUpper.startsWith(RESPMOD)) {
            sendMethodNotAllowed();
            return;
        }

        if (!methodLineUpper.startsWith(OPTIONS + " ")
                && !methodLineUpper.startsWith(REQMOD + " ")
                && !methodLineUpper.startsWith(RESPMOD + " ")) {
            sendBadRequest("Invalid ICAP Method Sintax");
            return;
        }

        String[] methodContent = methodLine.split("\\s");

        if (methodContent.length != 3) {
            sendBadRequest("Invalid ICAP Method Sintax");
            return;
        }

        String uri = methodContent[1];
        // [server, path&query]
        String[] uriParser = validateURI(uri);

        if (uriParser == null) {
            sendBadRequest("Invalid ICAP URI");
            return;
        }

        // parse headers exception start line, TODO more icap request headers to be supported
        for (int i = 1; i < entries.length; ++i) {
            String icapHeader = entries[i];
            if (icapHeader.toLowerCase().startsWith("encapsulated:")) {
                encapsulatedHeader = icapHeader.substring(icapHeader.indexOf(':') + 1).trim();
                continue;
            }
            if (icapHeader.toLowerCase().startsWith("preview:")) {
                previewHeader = icapHeader.substring(icapHeader.indexOf(':') + 1).trim();
                continue;
            }
        }

        if (encapsulatedHeader == null) {
            sendBadRequest("Invalid ICAP Requirements: <Encapsulated> Header not found");
            return;
        }

        if (previewHeader != null) {
            try {
                Integer.parseInt(previewHeader);
            } catch (NumberFormatException e) {
                sendBadRequest("Invalid ICAP Sintax: <Preview> Header not numeric");
                return;
            }
        }

        // TODO methods should be extensible
        if (methodLineUpper.startsWith(OPTIONS)) {

            handleOptions(entries, uriParser);

        } else if (methodLineUpper.startsWith(REQMOD)) {

            prepareHandleRequestModification(entries, uriParser);

        } else if (methodLineUpper.startsWith(RESPMOD)) {

            prepareHandleResponseModification(entries, uriParser);

        }

    }

    private void finishResponse() throws IOException {
        out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
    }

    private void sendCloseConnection() throws IOException {
        out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write(("Encapsulated: null-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
    }

    private void sendContinue() throws IOException {
        out.write("ICAP/1.0 100 Continue\r\n".getBytes(StandardCharsets.US_ASCII));
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
    }

    private void sendBadRequest(String cause) throws IOException {
        out.write("ICAP/1.0 400 Bad request\r\n".getBytes(StandardCharsets.US_ASCII));
        if (cause == null) {
            sendCloseConnection();
        } else {
            out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("Encapsulated: opt-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write((Integer.toHexString(cause.length()) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write((cause + "\r\n").getBytes(StandardCharsets.US_ASCII));
            finishResponse();
        }
    }

    private void sendServiceNotFound() throws IOException {
        out.write("ICAP/1.0 404 Service not found\r\n".getBytes(StandardCharsets.US_ASCII));
        sendCloseConnection();
    }

    private void sendMethodNotAllowed() throws IOException {
        out.write("ICAP/1.0 405 Method not allowed\r\n".getBytes(StandardCharsets.US_ASCII));
        sendCloseConnection();
    }

    private void sendServerError(String cause) throws IOException {
        out.write("ICAP/1.0 500 Server Error\r\n".getBytes(StandardCharsets.US_ASCII));
        if (cause == null) {
            sendCloseConnection();
        } else {
            out.write("Connection: close\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write(("Encapsulated: opt-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            out.write((Integer.toHexString(cause.length()) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write((cause + "\r\n").getBytes(StandardCharsets.US_ASCII));
            finishResponse();
        }
    }

    // returns: String[server, path]
    private String[] validateURI(String uri) {

        Pattern uriPattern = Pattern.compile("icap:\\/\\/(.*)(\\/.*)");
        Matcher uriMatcher = uriPattern.matcher(uri);

        if (!uriMatcher.matches()) {
            return null;
        }

        if (uriMatcher.groupCount() > 1) {
            return new String[]{uriMatcher.group(1), uriMatcher.group(2).substring(1)};
        } else {
            return new String[]{uriMatcher.group(1), ""};
        }

    }

    private void handleOptions(
            String[] entries,
            String[] uriParser) throws Exception {

        String service = uriParser[1];
        String service2 = service.toLowerCase();

        // TODO endpoints should be extensible
        if (!service2.startsWith("info")
                && !service2.startsWith("echo")
                && !service2.startsWith("virus_scan")) {

            sendServiceNotFound();
            return;

        }

        String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

        out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Date: " + date + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(SERVER_HEADER.getBytes(StandardCharsets.US_ASCII));

        // TODO endpoints and method could be extensible
        if (service2.startsWith("info")) {
            out.write(("Methods: " + RESPMOD + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else if (service2.startsWith("echo")) {
            out.write(("Methods: " + REQMOD + ", " + RESPMOD + "\r\n").getBytes(StandardCharsets.US_ASCII));
        } else if (service2.startsWith("virus_scan")) {
            out.write(("Methods: " + REQMOD + ", " + RESPMOD + "\r\n").getBytes(StandardCharsets.US_ASCII));
        }

        out.write(SERVICE_RESP_HEADER);
        // TODO ISTag is somewhat a session mechanism, not only a random string
        out.write(("ISTag:\"" + Utils.INSTANCE.randomUUID32Chars() + "\"\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Allow: 204\r\n").getBytes(StandardCharsets.US_ASCII));
        // TODO preview data should be supported in future
        out.write(("Preview: 0\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Transfer-Complete: *\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Encapsulated: null-body=0\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("\r\n").getBytes(StandardCharsets.US_ASCII));

        methodInProgress = OPTIONS;

    }

    private void prepareHandleRequestModification(
            String[] entries,
            String[] uriParser) throws Exception {

        String service = uriParser[1];
        String service2 = service.toLowerCase();

        // TODO endpoints should be extensible, the error msg reported here is not accurate
        if (!service2.startsWith("echo")
                && !service2.startsWith("virus_scan")) {

            sendMethodNotAllowed();
            return;

        }

        serviceInProgress = service2;
        methodInProgress = REQMOD;

    }

    private void prepareHandleResponseModification(
            String[] entries,
            String[] uriParser) throws Exception {

        String service = uriParser[1];
        String service2 = service.toLowerCase();

        // TODO endpoints should be extensible, the error msg reported here is not accurate
        if (!service2.startsWith("info")
                && !service2.startsWith("echo")
                && !service2.startsWith("virus_scan")) {

            sendMethodNotAllowed();
            return;

        }

        serviceInProgress = service2;
        methodInProgress = RESPMOD;

    }

    private void continueRequestModification() throws Exception {

        if (serviceInProgress.startsWith("virus_scan")) {
            findThreatsInPayload();
        }

        String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

        // TODO endpoints should be extensible in future

        if (serviceInProgress.startsWith("echo") && httpRequestBody.size() == 0) {
            out.write(("ICAP/1.0 204 No Content\r\n").getBytes(StandardCharsets.US_ASCII));
        } else {
            out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
        }

        out.write(("Date: " + date + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(SERVER_HEADER.getBytes(StandardCharsets.US_ASCII));
        out.write(("ISTag:\"" + Utils.INSTANCE.randomUUID32Chars() + "\"\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Connection: close\r\n").getBytes(StandardCharsets.US_ASCII));

        if (serviceInProgress.startsWith("echo")) {
            completeHandleEcho();
        } else if (serviceInProgress.startsWith("virus_scan")) {
            completeHandleVirusScan();
        }

    }

    private void continueResponseModification() throws Exception {

        if (serviceInProgress.startsWith("virus_scan")) {
            findThreatsInPayload();
        }

        String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());

        // TODO endpoints should be extensible in future

        if (serviceInProgress.startsWith("echo") && httpResponseBody.size() == 0) {
            out.write(("ICAP/1.0 204 No Content\r\n").getBytes(StandardCharsets.US_ASCII));
        } else {
            out.write(("ICAP/1.0 200 OK\r\n").getBytes(StandardCharsets.US_ASCII));
        }

        out.write(("Date: " + date + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(SERVER_HEADER.getBytes(StandardCharsets.US_ASCII));
        out.write(("ISTag: \"" + Utils.INSTANCE.randomUUID32Chars() + "\"\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write(("Connection: close\r\n").getBytes(StandardCharsets.US_ASCII));

        if (serviceInProgress.startsWith("info")) {
            completeHandleInfo(date);
        } else if (serviceInProgress.startsWith("echo")) {
            completeHandleEcho();
        } else if (serviceInProgress.startsWith("virus_scan")) {
            completeHandleVirusScan();
        }

    }

    private void completeHandleInfo(String date) throws Exception {

        StringBuilder httpResponseBody = new StringBuilder();

        httpResponseBody.append("OPTIONS icap://" + localIp + "/info ICAP/1.0\r\n");
        httpResponseBody.append("OPTIONS icap://" + localIp + "/echo ICAP/1.0\r\n");
        httpResponseBody.append("OPTIONS icap://" + localIp + "/virus_scan ICAP/1.0\r\n");

        httpResponseBody.append("REQMOD icap://" + localIp + "/echo ICAP/1.0\r\n");
        httpResponseBody.append("REQMOD icap://" + localIp + "/virus_scan ICAP/1.0\r\n");

        httpResponseBody.append("RESPMOD icap://" + localIp + "/info ICAP/1.0\r\n");
        httpResponseBody.append("RESPMOD icap://" + localIp + "/echo ICAP/1.0\r\n");
        httpResponseBody.append("RESPMOD icap://" + localIp + "/virus_scan ICAP/1.0\r\n");

        httpResponseBody.append("\r\n");

        StringBuilder chunkedBody = new StringBuilder()
                .append(Integer.toHexString(httpResponseBody.length()))
                .append("\r\n")
                .append(httpResponseBody);

        StringBuilder httpResponseHeader = new StringBuilder();

        httpResponseHeader.append("HTTP/1.1 200 OK\r\n");
        httpResponseHeader.append(("Date: " + date + "\r\n"));
        httpResponseHeader.append((SERVER_HEADER));
        httpResponseHeader.append(("Content-Type: text/plain\r\n"));
        httpResponseHeader.append(("Content-Length: " + httpResponseBody.length() + "\r\n"));
        httpResponseHeader.append(VIA_HEADER);
        httpResponseHeader.append("\r\n");

        out.write(("Encapsulated: res-hdr=0, res-body=" + httpResponseHeader.length() + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

        out.write(httpResponseHeader.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(chunkedBody.toString().getBytes(StandardCharsets.US_ASCII));

    }

    private void completeHandleEcho() throws Exception {

        StringBuilder encapsulatedHeaderEcho = new StringBuilder();

        int offset = 0;

        if (httpRequestHeaders.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("req-hdr=").append(offset);
            offset += httpRequestHeaders.size();
        }

        ByteArrayOutputStream outHttpRequestBody = new ByteArrayOutputStream();
        if (httpRequestBody.size() > 0) {
            outHttpRequestBody.write((Integer.toHexString(httpRequestBody.size()) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            outHttpRequestBody.write(httpRequestBody.toByteArray());
            outHttpRequestBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("req-body=").append(offset);
            offset += outHttpRequestBody.size();
        }

        if (httpResponseHeaders.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("res-hdr=").append(offset);
            offset += httpResponseHeaders.size();
        }

        ByteArrayOutputStream outHttpResponseBody = new ByteArrayOutputStream();
        if (httpResponseBody.size() > 0) {
            outHttpResponseBody.write((Integer.toHexString(httpResponseBody.size()) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            outHttpResponseBody.write(httpResponseBody.toByteArray());
            outHttpResponseBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("res-body=").append(offset);
            offset += outHttpResponseBody.size();
        }

        if (httpRequestBody.size() == 0 && httpResponseBody.size() == 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("null-body=").append(offset);
        }

        out.write(("Encapsulated: " + encapsulatedHeaderEcho + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

        boolean eof = false;
        if (httpRequestHeaders.size() > 0) {
            eof = true;
            out.write(httpRequestHeaders.toByteArray());
        }

        if (outHttpRequestBody.size() > 0) {
            eof = true;
            out.write(outHttpRequestBody.toByteArray());
        }

        if (httpResponseHeaders.size() > 0) {
            eof = true;
            out.write(httpResponseHeaders.toByteArray());
        }

        if (outHttpResponseBody.size() > 0) {
            eof = true;
            out.write(outHttpResponseBody.toByteArray());
        }

        if (eof) {
            finishResponse();
        }

    }

    private void completeHandleVirusScan() throws Exception {

        StringBuilder encapsulatedHeaderEcho = new StringBuilder();

        int offset = 0;

        ByteArrayOutputStream outHttpRequestHeaders = new ByteArrayOutputStream();
        ByteArrayOutputStream outHttpRequestBody = new ByteArrayOutputStream();
        ByteArrayOutputStream outHttpResponseHeaders = new ByteArrayOutputStream();
        ByteArrayOutputStream outHttpResponseBody = new ByteArrayOutputStream();

        if (icapThreatsHeader.size() > 0) {
            outHttpResponseHeaders.write("HTTP/1.1 403 Forbidden\r\n".getBytes(StandardCharsets.US_ASCII));
        } else {
            outHttpResponseHeaders.write("HTTP/1.1 200 OK\r\n".getBytes(StandardCharsets.US_ASCII));
        }

        outHttpResponseHeaders.write(SERVER_HEADER.getBytes(StandardCharsets.US_ASCII));

        StringBuilder responseMessage = new StringBuilder("");

        if (threatName != null) {

            responseMessage.append("Virus Found: ").append(threatName).append("\n");

            outHttpResponseHeaders.write(("Content-Type: text/plain\r\n").getBytes(StandardCharsets.US_ASCII));
            outHttpResponseHeaders.write(("Content-Length: " + responseMessage.length() + "\r\n").getBytes(StandardCharsets.US_ASCII));

            outHttpResponseBody.write((Integer.toHexString(responseMessage.length()) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            outHttpResponseBody.write(responseMessage.toString().getBytes(StandardCharsets.US_ASCII));
            outHttpResponseBody.write("\r\n".getBytes(StandardCharsets.US_ASCII));

        }

        outHttpResponseHeaders.write(VIA_HEADER.getBytes(StandardCharsets.US_ASCII));

        if (icapThreatsHeader.size() > 0) {
            outHttpResponseHeaders.write(icapThreatsHeader.toByteArray());
        }

        outHttpResponseHeaders.write("\r\n".getBytes(StandardCharsets.US_ASCII));

        if (outHttpRequestHeaders.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("req-hdr=").append(offset);
            offset += outHttpRequestHeaders.size();
        }

        if (outHttpRequestBody.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("req-body=").append(offset);
            offset += outHttpRequestBody.size();
        }

        if (outHttpResponseHeaders.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("res-hdr=").append(offset);
            offset += outHttpResponseHeaders.size();
        }

        if (outHttpResponseBody.size() > 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("res-body=").append(offset);
            offset += outHttpResponseBody.size();
        }

        if (outHttpRequestBody.size() == 0 && outHttpResponseBody.size() == 0) {
            if (encapsulatedHeaderEcho.length() > 0) encapsulatedHeaderEcho.append(", ");
            encapsulatedHeaderEcho.append("null-body=").append(offset);
        }

        out.write(("Encapsulated: " + encapsulatedHeaderEcho + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.write("\r\n".getBytes(StandardCharsets.US_ASCII));

        boolean eof = false;
        if (outHttpRequestHeaders.size() > 0) {
            eof = true;
            out.write(outHttpRequestHeaders.toByteArray());
        }

        if (outHttpRequestBody.size() > 0) {
            eof = true;
            out.write(outHttpRequestBody.toByteArray());
        }

        if (outHttpResponseHeaders.size() > 0) {
            eof = true;
            out.write(outHttpResponseHeaders.toByteArray());
        }

        if (outHttpResponseBody.size() > 0) {
            eof = true;
            out.write(outHttpResponseBody.toByteArray());
        }

        if (eof) {
            finishResponse();
        }

    }

    private ByteArrayOutputStream icapThreatsHeader = new ByteArrayOutputStream();
    private String threatName = null;

    private void findThreatsInPayload() throws Exception {
        final String environment =
                "true".equals(System.getProperty("testMode"))
                        ? Optional.ofNullable(System.getProperty("test.os.name")).orElse(System.getProperty("os.name"))
                        : System.getProperty("os.name");

        if (environment.toLowerCase().contains("windows")) {
            findThreatsInPayloadOnWindows();
        } else {
            findThreatsInPayloadOnLinux();
        }

    }

    private void findThreatsInPayloadOnWindows() throws Exception {

        WindowsDefenderAntivirus antivirus = new WindowsDefenderAntivirus();

        WindowsDefenderResponse response = null;

        if (httpRequestBody.size() > 0) {
            response = antivirus.checkThreat(httpRequestBody.toByteArray());
        } else if (httpResponseBody.size() > 0) {
            response = antivirus.checkThreat(httpResponseBody.toByteArray());
        }

        for (String threat : response.getThreatList()) {
            threatName = threat;
            icapThreatsHeader.write(("X-Threat-Description: " + threatName + "\r\n").getBytes(StandardCharsets.US_ASCII));
            icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes(StandardCharsets.US_ASCII));
            icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes(StandardCharsets.US_ASCII));
            break;
        }

    }

    private void findThreatsInPayloadOnLinux() throws Exception {

        ClamAVCore antivirus = new ClamAVCore();

        ClamAVResponse response = null;

        if (httpRequestBody.size() > 0) {
            response = antivirus.checkThreat(httpRequestBody.toByteArray());
        } else if (httpResponseBody.size() > 0) {
            response = antivirus.checkThreat(httpResponseBody.toByteArray());
        }

        if (response.getThreat() != null) {
            threatName = response.getThreat();
            icapThreatsHeader.write(("X-Threat-Description: " + threatName + "\r\n").getBytes(StandardCharsets.US_ASCII));
            icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes(StandardCharsets.US_ASCII));
            icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes(StandardCharsets.US_ASCII));
        }

    }

    //----------------------------------------

    private static void shiftLeftByOne(int[] c) {
        for (int i = 1; i < c.length; ++i) c[i - 1] = c[i];
    }

    public static void main(String[] args) throws Exception {
        Worker.main(args);
    }

}
