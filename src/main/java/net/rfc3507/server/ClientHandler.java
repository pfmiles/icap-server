package net.rfc3507.server;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.rfc3507.av.clamav.ClamAVCore;
import net.rfc3507.av.clamav.ClamAVResponse;
import net.rfc3507.av.windowsdefender.WindowsDefenderAntivirus;
import net.rfc3507.av.windowsdefender.WindowsDefenderResponse;

public class ClientHandler implements Runnable {
	
	private Socket client;
	
	private InputStream in;
	private OutputStream out;
	private String serverName;
	
	public ClientHandler(Socket c) {
		this.client = c;
		try {
			serverName = Inet4Address.getLocalHost().getHostName();
		} catch(IOException e) {
			warning("\n### SERVER ### [Startup] [WARNING]\n" +  e.getMessage());
			serverName = "localhost";
		}
	}

	@Override
	public void run() {
		
		try {
			in = client.getInputStream();
			out = client.getOutputStream();
			handle();
			out.close();
			in.close();
		} catch(IOException e) {
			warning("\n### SERVER ### [Cleanup] [WARNING] General error:\n" + e.getMessage());
		}
		
		try {
			client.close();
		} catch(IOException e) {
			warning("\n### SERVER ### [Cleanup] [WARNING] General error:\n" + e.getMessage());
		}
		
	}
	
	private static final String OPTIONS = "OPTIONS";
	private static final String REQMOD  = "REQMOD";
	private static final String RESPMOD = "RESPMOD";
	
	private String methodInProgress = null;
	private String serviceInProgress = null;
	
	private String encapsulatedHeader = null;
	private String previewHeader = null;
	
	private ByteArrayOutputStream httpRequestHeaders = null;
	private ByteArrayOutputStream httpRequestBody = null;
	private ByteArrayOutputStream httpResponseHeaders = null;
	private ByteArrayOutputStream httpResponseBody = null;
	
	private void handle() throws IOException {

		while(true) {
			
			httpRequestHeaders = new ByteArrayOutputStream();
			httpRequestBody = new ByteArrayOutputStream();
			httpResponseHeaders = new ByteArrayOutputStream();
			httpResponseBody = new ByteArrayOutputStream();
			
			methodInProgress = null;
			
			try {
				startHandleIcapRequest();
				if( methodInProgress != null ) {
					continueHandleIcapRequest();
				}
				out.flush();
			} catch(IOException e) {
				e.printStackTrace();
				break;
			} catch(Exception e) {
				sendServerError(e.getMessage());
			}
			
			if( OPTIONS.equals(methodInProgress) ) {
				continue;
			}
			break;
		}
		
	}
	
	private void startHandleIcapRequest() throws Exception {
		
		ByteArrayOutputStream cache = new ByteArrayOutputStream();
		
		int reader = -1;
		while( (reader = in.read()) != -1) {
			
			cache.write(reader);
			
			byte[] memory = cache.toByteArray();
			if( memory.length >= 4 ) {
				if(    memory[memory.length-4] == '\r' 
					&& memory[memory.length-3] == '\n' 
					&& memory[memory.length-2] == '\r' 
					&& memory[memory.length-1] == '\n' ) {
					
					info("### (SERVER: RECEIVE) ### ICAP REQUEST\n"+new String(memory));
					
					analyseRequestHeader(memory);
					break;
					
				}
			}
			
		}
		
	}
	
	private void continueHandleIcapRequest() throws Exception {
		
		extractEncapsulatedPayloads();
		
		if( REQMOD.equals(methodInProgress) ) {
			continueRequestModification();
		} else if( RESPMOD.equals(methodInProgress) ) {
			continueResponseModification();
		}
		
	}
	
	private void extractEncapsulatedPayloads() throws Exception {

        int httpRequestHeaderSize = 0;
        int httpResponseHeaderSize = 0;
        
        String lastOffsetLabel = "";
        
        int lastOffsetValue = 0;
        
        String[] encapsulatedValues = encapsulatedHeader.split(",");
        
        for(String offset: encapsulatedValues) {
        	
        	String offsetParser[] = offset.split("=");
        	
        	String offsetLabel = offsetParser[0].trim();
        	
        	int offsetValue = Integer.parseInt(offsetParser[1].trim());
        	
        	switch(lastOffsetLabel) {
        		
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
        
        byte[] parseContent = null;
        
        if( httpRequestHeaderSize > 0 ) {
        	parseContent = new byte[httpRequestHeaderSize];
        	readStream(parseContent);
        	info("### (SERVER: RECEIVE) ### HTTP REQUEST HEADER\n"+new String(parseContent));
        	httpRequestHeaders.write(parseContent);
        }
        
        if( httpResponseHeaderSize > 0 ) {
        	parseContent = new byte[httpResponseHeaderSize];
        	readStream(parseContent);
        	info("### (SERVER: RECEIVE) ### HTTP RESPONSE HEADER\n"+new String(parseContent));
        	httpResponseHeaders.write(parseContent);
        }
		
		if( "req-body".equals(lastOffsetLabel) ) {
			readBody(httpRequestBody);
			info("### (SERVER: RECEIVE) ### HTTP REQUEST BODY\n"+new String(httpRequestBody.toByteArray()));
		}
		
		if( "res-body".equals(lastOffsetLabel) ) {
			readBody(httpResponseBody); 
			info("### (SERVER: RECEIVE) ### HTTP RESPONSE BODY\n"+new String(httpResponseBody.toByteArray()));
		}
		
	}
	
	private void readBody(OutputStream out) throws Exception {
        
        boolean previewIsEnough = false;
        
		if( previewHeader != null ) {
			/*
			 * Read preview payload
			 */
			int contentPreview = Integer.parseInt(previewHeader);
			previewIsEnough = extractBody(out, contentPreview);
			if( ! previewIsEnough ){
				sendContinue();
			}
		}
		
		if( !previewIsEnough ) {
			/*
			 * Read remaining body payload
			 */
			extractBody(out, -1);
		}
		
	}
	
	private boolean extractBody(OutputStream out, int previewSize) throws Exception {
		
		ByteArrayOutputStream backupDebug = new ByteArrayOutputStream(); 
		
		StringBuilder line = new StringBuilder("");
		
		byte[] cache = null;
		
		int mark[] = new int[2];
		reset(mark);
		
		StringBuilder control = new StringBuilder("");
		
		while(true) {
			
			int reader = in.read();
			shift(mark);
			mark[1] = reader;
			
			backupDebug.write(reader);
			
			control.append((char)reader);
			
			if( reader == ';' ) {
				continue;
			}
			
			if( reader == ' ' || reader == 'i' ){
				continue;
			}
			
			if( reader == 'e' ) {
				if(control.toString().equals("0; ie")) {
					continue;
				}
			}
			
			if( reader == 'f' ) {
				if(control.toString().equals("0; ieof")) {
					continue;
				}
			}
			
			if( reader == '\r' ) {
				continue;
			}
			
			if(    mark[0] == '\r'
				&& mark[1] == '\n' ) {
				
				if( control.toString().equals("0; ieof\r\n\r\n") ) {
					return true;
				}
				
				if( control.toString().startsWith("0; ieof") ) {
					continue;
				}
				
				if( line.length() == 0 ) {
					return false;
				}
				
				int amountRead = Integer.parseInt(line.toString(), 16);

				if(amountRead > 0) {
					cache = new byte[amountRead];
					readStream(cache);
					out.write(cache);
					backupDebug.write(cache);
				}
				
				int cr = -1, lf = -1;
				cr = in.read(); lf = in.read();
				backupDebug.write(cr); backupDebug.write(lf);
				
				if( cr != '\r' || lf != '\n' ) {
					throw new Exception("Error reading end of chunk");
				}
				
				if( amountRead > 0 ) {
					control = new StringBuilder("");
				} else {
					control.append((char)cr);
					control.append((char)lf);
				}
				
				if( control.toString().equals("0\r\n\r\n")) {
					return false;
				}
				
				line = new StringBuilder("");
				
				continue;
				
			}
			
			line.append((char)reader);
			
		}
		
	}
	
	private void analyseRequestHeader(byte[] memory) throws Exception {

		String data = new String(memory);

		String[] entries = data.split("\\r\\n");
		
		if( entries.length == 0 ) {
			sendBadRequest("Invalid ICAP Request");
			return;
		}
		
		String methodLine = entries[0];
		String methodLine2 = methodLine.toUpperCase();
		
		if( ! methodLine2.startsWith(OPTIONS) 
				&& ! methodLine2.startsWith(REQMOD) 
				&& ! methodLine2.startsWith(RESPMOD) ) {
			sendMethodNotAllowed();
			return;
		}
		
		if( ! methodLine2.startsWith(OPTIONS+" ") 
				&& ! methodLine2.startsWith(REQMOD+" ") 
				&& ! methodLine2.startsWith(RESPMOD+" ") ) {
			sendBadRequest("Invalid ICAP Method Sintax");
			return;
		}
		
		String[] methodContent = methodLine.split("\\s");
		
		if( methodContent.length != 3 ) {
			sendBadRequest("Invalid ICAP Method Sintax");
			return;
		}
		
		String uri = methodContent[1];
		String[] uriParser = validateURI(uri);
		
		if( uriParser == null ) {
			sendBadRequest("Invalid ICAP URI");
			return;
		}
		
		for(int i = 1; i < entries.length; ++i ) {
			String icapHeader = entries[i]; 
			if( icapHeader.toLowerCase().startsWith("encapsulated:") ) {
				encapsulatedHeader = icapHeader.substring(icapHeader.indexOf(':')+1).trim();
				continue;
			}
			if( icapHeader.toLowerCase().startsWith("preview:") ) {
				previewHeader = icapHeader.substring(icapHeader.indexOf(':')+1).trim();
				continue;
			}
		}
		
		if( encapsulatedHeader == null ) {
			sendBadRequest("Invalid ICAP Requirements: <Encapsulated> Header not found");
			return;
		}
		
		if( previewHeader != null ) {
			try {
				Integer.parseInt(previewHeader);
			} catch(NumberFormatException e){
				sendBadRequest("Invalid ICAP Sintax: <Preview> Header not numeric");
				return;
			}
		}
		
		if( methodLine2.startsWith(OPTIONS) ) {
			
			handleOptions(entries, uriParser);
			
		} else if( methodLine2.startsWith(REQMOD) ) {
			
			handleRequestModification(entries, uriParser);
			
		} else if( methodLine2.startsWith(RESPMOD) ) {
			
			handleResponseModification(entries, uriParser);
			
		}
		
	}
	
	private void finishResponse() throws IOException {
		out.write("0\r\n\r\n".getBytes());
	}
	
	private void sendCloseConnection() throws IOException {
		out.write("Connection: close\r\n".getBytes());
		out.write(("Encapsulated: null-body=0\r\n").getBytes());
		out.write("\r\n".getBytes());
	}
	
	private void sendContinue() throws IOException {
		info("### (SERVER: SEND) ### ICAP RESPONSE: 100 Continue");
		out.write("ICAP/1.0 100 Continue\r\n".getBytes());
		out.write("\r\n".getBytes());
	}
	
	private void sendBadRequest(String cause) throws IOException {
		info("### (SERVER: SEND) ### ICAP RESPONSE: 400 Bad request");
		out.write("ICAP/1.0 400 Bad request\r\n".getBytes());
		if( cause == null ) {
			sendCloseConnection();
		} else {
			out.write("Connection: close\r\n".getBytes());
			out.write(("Encapsulated: opt-body=0\r\n").getBytes());
			out.write("\r\n".getBytes());
			out.write((Integer.toHexString(cause.length())+"\r\n").getBytes());
			out.write((cause+"\r\n").getBytes());
			finishResponse();
		}
	}
	
	private void sendServiceNotFound() throws IOException {
		info("### (SERVER: SEND) ### ICAP RESPONSE: 404 Service not found");
		out.write("ICAP/1.0 404 Service not found\r\n".getBytes());
		sendCloseConnection();
	}
	
	private void sendMethodNotAllowed() throws IOException {
		info("### (SERVER: SEND) ### ICAP RESPONSE: 405 Method not allowed");
		out.write("ICAP/1.0 405 Method not allowed\r\n".getBytes());
		sendCloseConnection();
	}
	
	private void sendServerError(String cause) throws IOException {
		info("### (SERVER: SEND) ### ICAP RESPONSE: 500 Server Error");
		out.write("ICAP/1.0 500 Server Error\r\n".getBytes());
		if( cause == null ) {
			sendCloseConnection();
		} else {
			out.write("Connection: close\r\n".getBytes());
			out.write(("Encapsulated: opt-body=0\r\n").getBytes());
			out.write("\r\n".getBytes());
			out.write((Integer.toHexString(cause.length())+"\r\n").getBytes());
			out.write((cause+"\r\n").getBytes());
			finishResponse();
		}
	}
	
	private String[] validateURI(String uri) {
		
		Pattern uriPattern = Pattern.compile("icap:\\/\\/(.*)(\\/.*)");
		Matcher uriMatcher = uriPattern.matcher(uri);
		
		if( ! uriMatcher.matches() ) {
			return null;
		}
		
		if( uriMatcher.groupCount() > 1 ) {
			return new String[] { uriMatcher.group(1), uriMatcher.group(2).substring(1) };
		} else {
			return new String[] { uriMatcher.group(1), "" };
		}
		
	}
	
	private void handleOptions(
			String[] entries,
			String[] uriParser) throws Exception {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("info") 
				&& !service2.startsWith("echo") 
				&& !service2.startsWith("virus_scan") ) {
			
			sendServiceNotFound();
			return;
			
		}
			
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		info("### (SERVER: SEND) ### ICAP RESPONSE: 200 OK");
		
		out.write(("ICAP/1.0 200 OK\r\n").getBytes());
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: "+serverName+"\r\n").getBytes());
		
		if( service2.startsWith("info")) {
			out.write(("Methods: "+RESPMOD+"\r\n").getBytes());
		} else if( service2.startsWith("echo")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes());
		} else if( service2.startsWith("virus_scan")) {
			out.write(("Methods: "+REQMOD+", "+RESPMOD+"\r\n").getBytes());
		}
		
		out.write(("Service: Java-Tech-Server/1.0\r\n").getBytes());
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Allow: 204\r\n").getBytes());
		out.write(("Preview: 0\r\n").getBytes());
		out.write(("Transfer-Complete: *\r\n").getBytes());
		out.write(("Encapsulated: null-body=0\r\n").getBytes());
		out.write(("\r\n").getBytes());
		
		methodInProgress = OPTIONS;
		
	}
	
	private void handleRequestModification(
			String[] entries,
			String[] uriParser) throws Exception {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("echo") 
				&& !service2.startsWith("virus_scan") ) {
			
			sendMethodNotAllowed();
			return;
			
		}
		
		serviceInProgress = service2;
		methodInProgress = REQMOD;
		
	}
	
	private void handleResponseModification(
			String[] entries,
			String[] uriParser) throws Exception {
		
		String service = uriParser[1];
		String service2 = service.toLowerCase();
		
		if( !service2.startsWith("info")
				&& !service2.startsWith("echo")
				&& !service2.startsWith("virus_scan") ) {
			
			sendMethodNotAllowed();
			return;
			
		}
		
		serviceInProgress = service2;
		methodInProgress = RESPMOD;
		
	}
	
	private void continueRequestModification() throws Exception {
		
		if( serviceInProgress.startsWith("virus_scan") ) {
			findThreatsInPayload();
		}
		
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		if( serviceInProgress.startsWith("echo") && httpRequestBody.size() == 0 ) {
			info("### (SERVER: SEND) ### ICAP RESPONSE: 204 No Content");
			out.write(("ICAP/1.0 204 No Content\r\n").getBytes());
		} else {
			info("### (SERVER: SEND) ### ICAP RESPONSE: 200 OK");
			out.write(("ICAP/1.0 200 OK\r\n").getBytes());
		}
		
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: "+serverName+"\r\n").getBytes());
		out.write(("ISTag:\"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Connection: close\r\n").getBytes());
		
		if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}
		
	}
	
	private void continueResponseModification() throws Exception {
		
		if( serviceInProgress.startsWith("virus_scan") ) {
			findThreatsInPayload();
		}
		
		String date = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss Z", Locale.US).format(new Date());
		
		if( serviceInProgress.startsWith("echo") && httpResponseBody.size() == 0 ) {
			
			info("### (SERVER: SEND) ### ICAP RESPONSE: 204 No Content");
			out.write(("ICAP/1.0 204 No Content\r\n").getBytes());
			
		} else {
			
			info("### (SERVER: SEND) ### ICAP RESPONSE: 200 OK");
			out.write(("ICAP/1.0 200 OK\r\n").getBytes());
			
		}
		
		out.write(("Date: "+date+"\r\n").getBytes());
		out.write(("Server: "+serverName+"\r\n").getBytes());
		out.write(("ISTag: \"ALPHA-B123456-GAMA\"\r\n").getBytes());
		out.write(("Connection: close\r\n").getBytes());
		
		if( serviceInProgress.startsWith("info") ) {
			completeHandleInfo(date);
		} else if( serviceInProgress.startsWith("echo") ) {
			completeHandleEcho();
		} else if( serviceInProgress.startsWith("virus_scan") ) {
			completeHandleVirusScan();
		}
		
	}
	
	private void completeHandleInfo(String date) throws Exception {
		
		StringBuilder httpResponseBody = new StringBuilder();
		
		httpResponseBody.append("OPTIONS icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("OPTIONS icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		
		httpResponseBody.append("REQMOD icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("REQMOD icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		
		httpResponseBody.append("RESPMOD icap://"+serverName+"/info ICAP/1.0\r\n");
		httpResponseBody.append("RESPMOD icap://"+serverName+"/echo ICAP/1.0\r\n");
		httpResponseBody.append("RESPMOD icap://"+serverName+"/virus_scan ICAP/1.0\r\n");
		
		httpResponseBody.append("\r\n");
		
		StringBuilder chunkedBody = new StringBuilder()
				.append( Integer.toHexString(httpResponseBody.length()) )
				.append("\r\n")
				.append(httpResponseBody);
		
		StringBuilder httpResponseHeader = new StringBuilder();
		
		httpResponseHeader.append("HTTP/1.1 200 OK\r\n");
		httpResponseHeader.append(("Date: "+date+"\r\n"));
		httpResponseHeader.append(("Server: "+serverName+"\r\n"));
		httpResponseHeader.append(("Content-Type: text/plain\r\n"));
		httpResponseHeader.append(("Content-Length: "+httpResponseBody.length()+"\r\n"));
		httpResponseHeader.append(("Via: 1.0 "+serverName+"\r\n"));
		httpResponseHeader.append("\r\n");
		
		out.write(("Encapsulated: res-hdr=0, res-body="+httpResponseHeader.length()+"\r\n").getBytes());
		out.write("\r\n".getBytes());
		
		out.write(httpResponseHeader.toString().getBytes());
		out.write(chunkedBody.toString().getBytes());
		
	}
	
	private void completeHandleEcho() throws Exception {
		
		StringBuilder encapsulatedHeaderEcho = new StringBuilder();
		
		int offset = 0;
		
		if(httpRequestHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-hdr=").append(offset);
			offset += httpRequestHeaders.size(); 
		}
		
		ByteArrayOutputStream outHttpRequestBody = new ByteArrayOutputStream();
		if( httpRequestBody.size() > 0 ) {
			outHttpRequestBody.write((Integer.toHexString(httpRequestBody.size())+"\r\n").getBytes());
			outHttpRequestBody.write(httpRequestBody.toByteArray());
			outHttpRequestBody.write("\r\n".getBytes());
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-body=").append(offset);
			offset += outHttpRequestBody.size();
		}
		
		if(httpResponseHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-hdr=").append(offset);
			offset += httpResponseHeaders.size(); 
		}
		
		ByteArrayOutputStream outHttpResponseBody = new ByteArrayOutputStream();
		if( httpResponseBody.size() > 0 ) {
			outHttpResponseBody.write((Integer.toHexString(httpResponseBody.size())+"\r\n").getBytes());
			outHttpResponseBody.write(httpResponseBody.toByteArray());
			outHttpResponseBody.write("\r\n".getBytes());
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-body=").append(offset);
			offset += outHttpResponseBody.size();
		}
		
		if( httpRequestBody.size() == 0 && httpResponseBody.size() == 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("null-body=").append(offset);
		}
		
		info("### (SERVER: SEND) ### ICAP RESPONSE HEADER\n<Encapsulated>: " + encapsulatedHeaderEcho);
		
		out.write(("Encapsulated: "+encapsulatedHeaderEcho+"\r\n").getBytes());
		out.write("\r\n".getBytes());
		
		boolean eof = false;
		if(httpRequestHeaders.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP REQUEST HEADER\n" + new String(httpRequestHeaders.toByteArray()));
			out.write(httpRequestHeaders.toByteArray());
		}
		
		if(outHttpRequestBody.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP REQUEST BODY\n" + new String(outHttpRequestBody.toByteArray()));
			out.write(outHttpRequestBody.toByteArray());
		}
		
		if(httpResponseHeaders.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP RESPONSE HEADER\n" + new String(httpResponseHeaders.toByteArray()));
			out.write(httpResponseHeaders.toByteArray());
		}
		
		if(outHttpResponseBody.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP RESPONSE BODY\n" + new String(outHttpResponseBody.toByteArray()));
			out.write(outHttpResponseBody.toByteArray());
		}
		
		if(eof) {
			finishResponse();
		}
		
	}
	
	private void completeHandleVirusScan() throws Exception {
		
		StringBuilder encapsulatedHeaderEcho = new StringBuilder();
		
		int offset = 0;
		
		ByteArrayOutputStream outHttpRequestHeaders  = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpRequestBody     = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpResponseHeaders = new ByteArrayOutputStream();
		ByteArrayOutputStream outHttpResponseBody    = new ByteArrayOutputStream();
		
		if( icapThreatsHeader.size() > 0 ) {
			outHttpResponseHeaders.write("HTTP/1.1 403 Forbidden\r\n".getBytes());
		} else {
			outHttpResponseHeaders.write("HTTP/1.1 200 OK\r\n".getBytes());
		}
		
		outHttpResponseHeaders.write(("Server: "+serverName+"\r\n").getBytes());
		
		StringBuilder responseMessage = new StringBuilder("");
		
		if( threatName != null ) {
			
			responseMessage.append("Virus Found: ").append(threatName);
			
			outHttpResponseHeaders.write(("Content-Type: text/plain\r\n").getBytes());
			outHttpResponseHeaders.write(("Content-Length: "+responseMessage.length()+"\r\n").getBytes());
			
			outHttpResponseBody.write((Integer.toHexString(responseMessage.length())+"\r\n").getBytes());
			outHttpResponseBody.write(responseMessage.toString().getBytes());
			outHttpResponseBody.write("\r\n".getBytes());
			
		}
		
		outHttpResponseHeaders.write(("Via: "+serverName+"\r\n").getBytes());
		
		if( icapThreatsHeader.size() > 0 ) {
			outHttpResponseHeaders.write(icapThreatsHeader.toByteArray());
		}
		
		outHttpResponseHeaders.write("\r\n".getBytes());
		
		if(outHttpRequestHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-hdr=").append(offset);
			offset += outHttpRequestHeaders.size(); 
		}
		
		if( outHttpRequestBody.size() > 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("req-body=").append(offset);
			offset += outHttpRequestBody.size();
		}
		
		if(outHttpResponseHeaders.size() > 0) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-hdr=").append(offset);
			offset += outHttpResponseHeaders.size(); 
		}
		
		if( outHttpResponseBody.size() > 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("res-body=").append(offset);
			offset += outHttpResponseBody.size();
		}
		
		if( outHttpRequestBody.size() == 0 && outHttpResponseBody.size() == 0 ) {
			if(encapsulatedHeaderEcho.length()>0) encapsulatedHeaderEcho.append(", ");
			encapsulatedHeaderEcho.append("null-body=").append(offset);
		}
		
		info("### (SERVER: SEND) ### ICAP RESPONSE HEADER\n<Encapsulated>: " + encapsulatedHeaderEcho);
		
		out.write(("Encapsulated: "+encapsulatedHeaderEcho+"\r\n").getBytes());
		out.write("\r\n".getBytes());
		
		boolean eof = false;
		if(outHttpRequestHeaders.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP REQUEST HEADER\n" + new String(outHttpRequestHeaders.toByteArray()));
			out.write(outHttpRequestHeaders.toByteArray());
		}
		
		if(outHttpRequestBody.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP REQUEST BODY\n" + new String(outHttpRequestBody.toByteArray()));
			out.write(outHttpRequestBody.toByteArray());
		}
		
		if(outHttpResponseHeaders.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP RESPONSE HEADER\n" + new String(outHttpResponseHeaders.toByteArray()));
			out.write(outHttpResponseHeaders.toByteArray());
		}
		
		if(outHttpResponseBody.size() > 0) {
			eof = true;
			info("### (SERVER: SEND) ### ICAP RESPONSE: HTTP RESPONSE BODY\n" + new String(outHttpResponseBody.toByteArray()));
			out.write(outHttpResponseBody.toByteArray());
		}
		
		if(eof) {
			finishResponse();
		}
		
	}
	
	private ByteArrayOutputStream icapThreatsHeader = new ByteArrayOutputStream(); 
	private String threatName = null;
	
	private void findThreatsInPayload() throws Exception {
		
		System.out.println("[ICAP-SERVER] Checking Threats...");
		
		String environment = System.getProperty("java.os");
		
		if(environment.toLowerCase().contains("windows")) {
			System.out.println("[ICAP-SERVER] Checking Threats (Windows)...");
			findThreatsInPayloadOnWindows();
		} else {
			System.out.println("[ICAP-SERVER] Checking Threats (Linux)...");
			findThreatsInPayloadOnLinux();
		}
		
	}
	
	private void findThreatsInPayloadOnWindows() throws Exception {
		
		WindowsDefenderAntivirus antivirus = new WindowsDefenderAntivirus();
		
		WindowsDefenderResponse response = null;
		
		if( httpRequestBody.size() > 0 ) {
			response = antivirus.checkThreat(httpRequestBody.toByteArray());
		} else if( httpResponseBody.size() > 0 ) {
			response = antivirus.checkThreat(httpResponseBody.toByteArray());
		}

		for( String threat: response.getThreatList() ) {
			threatName = threat;
			icapThreatsHeader.write(("X-Threat-Description: "+threatName+"\r\n").getBytes());
			icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes());
			icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes());
			break;
		}
		
	}
	
	private void findThreatsInPayloadOnLinux() throws Exception {
		
		ClamAVCore antivirus = new ClamAVCore();
		
		ClamAVResponse response = null;
		
		if( httpRequestBody.size() > 0 ) {
			response = antivirus.checkThreat(httpRequestBody.toByteArray());
		} else if( httpResponseBody.size() > 0 ) {
			response = antivirus.checkThreat(httpResponseBody.toByteArray());
		}

		if( response.getThreat() != null ) {
			threatName = response.getThreat();
			icapThreatsHeader.write(("X-Threat-Description: "+threatName+"\r\n").getBytes());
			icapThreatsHeader.write(("X-Threat-Resolution: None\r\n").getBytes());
			icapThreatsHeader.write(("X-Threat-Type: Threat\r\n").getBytes());
		}
		
	}
	
	//----------------------------------------
	
	private void readStream(byte[] out) throws IOException {
		
		byte[] reading = null;
		ByteArrayOutputStream cache = new ByteArrayOutputStream();
		
		int total = out.length;
		while(total > 0) {
			int amount = total;
			int available = in.available();
			if(amount > available) {
				amount = available;
			}
			reading = new byte[amount];
			in.read(reading);
			cache.write(reading);
			total -= amount;
		}
		
		new ByteArrayInputStream(cache.toByteArray()).read(out);
		
	}
	
	private void info(String message) {
//		Logger.getGlobal().info(message);
	}
	
	private void warning(String message) {
		Logger.getGlobal().warning(message);
	}
	
	private static void reset( int[]c ){
		for(int i = 0; i < c.length; ++i) c[i]=-1;
	}
	
	private static void shift( int[]c ) {
		for( int i = 1; i < c.length; ++i ) c[i-1] = c[i];
	}
	
	public static void main(String[] args) throws Exception {
		Daemon.main(args);
	}
	
}
