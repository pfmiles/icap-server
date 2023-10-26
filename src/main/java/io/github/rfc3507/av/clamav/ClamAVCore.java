package io.github.rfc3507.av.clamav;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ClamAVCore {

	private static final Logger logger = LoggerFactory.getLogger(ClamAVCore.class);

	private final String id = UUID.randomUUID().toString();

	public String getId() {
		return id;
	}

	public ClamAVResponse checkThreat(byte[] content)
			throws ClamAVException {

		File file = saveContent(content);

		ClamAVResponse response = scanContent(file);

		file.delete();

		return response;

	}

	private File saveContent(byte[] content) throws ClamAVException {

		final File workDir = new File(System.getProperty("java.io.tmpdir"), getId());
		workDir.mkdirs();

		final File file = new File(workDir, "threat.data");

		try(final OutputStream out = new FileOutputStream(file)) {
			out.write(content);
			out.flush();
		} catch (Exception e) {
			throw new ClamAVException(e.getMessage());
		}

		return file;

	}

	private ClamAVResponse scanContent(File file) throws ClamAVException {
		final String path = file.getParent();

		logger.info("Scanning file: " + path + "/" + file.getName() + "...");

		final String testMode = System.getProperty("testMode");
		final String[] command = "true".equals(testMode) 
			? new String[] { "echo", "/tmp/eicar/eicar.com: Win.Test.EICAR_HDB-1 FOUND" }
			: new String[] { "/usr/bin/clamscan", "-vir", path };

		final Process process;
		try {
			process = Runtime.getRuntime().exec(command);
			process.waitFor();
		} catch (Exception e) {
			throw new ClamAVException(e.getMessage());
		}

		InputStream input = null;

		input = process.getInputStream();
		if (input == null) {
			input = process.getErrorStream();
		}

		final ByteArrayOutputStream response = new ByteArrayOutputStream();
		try {
			IOUtils.copy(input, response);
		} catch (IOException e) {
			throw new ClamAVException(e.getMessage());
		}

		final String checkResult = new String(response.toByteArray(), StandardCharsets.US_ASCII);

		final Pattern pattern = Pattern.compile(
				"\\s(\\S*)\\sFOUND$",
				Pattern.MULTILINE);

		final Matcher matcher = pattern.matcher(checkResult);

		final ClamAVResponse result = new ClamAVResponse();

		while (matcher.find()) {
			result.setThreat(matcher.group(1));
		}

		return result;

	}

}
