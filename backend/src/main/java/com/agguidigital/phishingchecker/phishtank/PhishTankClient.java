package com.agguidigital.phishingchecker.phishtank;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;

import com.agguidigital.phishingchecker.check.PhishTankDiagnostic;
import com.agguidigital.phishingchecker.check.PhishTankEvidence;
import com.agguidigital.phishingchecker.check.PhishTankStatus;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class PhishTankClient {

	public static final URI ENDPOINT = URI.create("https://checkurl.phishtank.com/checkurl/");

	public static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

	public static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(10);

	public static final int MAX_RESPONSE_BYTES = 1_048_576;

	public static final String DEFAULT_USER_AGENT = "phishing-checker (URL reputation lookup)";

	private static final int MAX_HEADER_LENGTH = 128;

	private final HttpClient httpClient;

	private final URI endpoint;

	private final Duration responseTimeout;

	private final int maxResponseBytes;

	private final ObjectMapper mapper = new ObjectMapper();

	public PhishTankClient(HttpClient httpClient, URI endpoint, Duration responseTimeout, int maxResponseBytes) {
		this.httpClient = httpClient;
		this.endpoint = endpoint;
		this.responseTimeout = responseTimeout;
		this.maxResponseBytes = maxResponseBytes;
	}

	public URI endpoint() {
		return endpoint;
	}

	public PhishTankOutcome lookup(String url, String appKey, String userAgent) {
		if (userAgent == null || userAgent.isBlank() || !allowedEndpoint(endpoint)) {
			return PhishTankOutcome.of(PhishTankStatus.unavailable);
		}
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder(endpoint)
					.version(HttpClient.Version.HTTP_1_1)
					.timeout(responseTimeout)
					.header("Accept", "application/json")
					.header("Content-Type", "application/x-www-form-urlencoded")
					.header("User-Agent", userAgent)
					.POST(HttpRequest.BodyPublishers.ofString(formBody(url, appKey)))
					.build();
		}
		catch (IllegalArgumentException ex) {
			return PhishTankOutcome.of(PhishTankStatus.unavailable);
		}
		try {
			HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
			String interval = header(response, "X-Request-Limit-Interval");
			String limit = header(response, "X-Request-Limit");
			String count = header(response, "X-Request-Count");
			int statusCode = response.statusCode();
			if (statusCode == 509) {
				closeQuietly(response.body());
				return PhishTankOutcome.of(PhishTankStatus.rate_limited, headersOnly(interval, limit, count));
			}
			if (statusCode != 200) {
				closeQuietly(response.body());
				return PhishTankOutcome.unavailable(PhishTankDiagnostic.provider_http_status, headersOnly(interval, limit, count), statusCode);
			}
			String body = readLimited(response.body());
			return interpret(body, interval, limit, count);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return PhishTankOutcome.of(PhishTankStatus.unavailable);
		}
		catch (IOException ex) {
			return PhishTankOutcome.unavailable(transportDiagnostic(ex));
		}
	}

	static PhishTankDiagnostic transportDiagnostic(IOException exception) {
		if (exception instanceof ResponseTooLargeException) {
			return PhishTankDiagnostic.oversized_response;
		}
		if (exception instanceof HttpTimeoutException) {
			return PhishTankDiagnostic.timeout;
		}
		return PhishTankDiagnostic.connection_failure;
	}

	static boolean allowedEndpoint(URI candidate) {
		if (candidate == null || candidate.getRawQuery() != null || candidate.getRawFragment() != null || candidate.getUserInfo() != null) {
			return false;
		}
		if (!"/checkurl/".equals(candidate.getPath())) {
			return false;
		}
		String host = candidate.getHost();
		if (host == null || host.isBlank()) {
			return false;
		}
		if ("https".equalsIgnoreCase(candidate.getScheme()) && "checkurl.phishtank.com".equalsIgnoreCase(host) && (candidate.getPort() == -1 || candidate.getPort() == 443)) {
			return true;
		}
		return "http".equalsIgnoreCase(candidate.getScheme()) && ("127.0.0.1".equals(host) || "localhost".equalsIgnoreCase(host)) && candidate.getPort() > 0;
	}

	private static String formBody(String url, String appKey) {
		StringBuilder form = new StringBuilder();
		form.append("url=").append(URLEncoder.encode(url, StandardCharsets.UTF_8));
		form.append("&format=json");
		if (appKey != null && !appKey.isBlank()) {
			form.append("&app_key=").append(URLEncoder.encode(appKey, StandardCharsets.UTF_8));
		}
		return form.toString();
	}

	private PhishTankOutcome interpret(String body, String interval, String limit, String count) {
		if (body == null || body.isBlank()) {
			return PhishTankOutcome.unavailable(PhishTankDiagnostic.invalid_json, headersOnly(interval, limit, count), null);
		}
		try {
			JsonNode root = mapper.readTree(body);
			if (root == null || !root.isObject()) {
				return PhishTankOutcome.unavailable(PhishTankDiagnostic.invalid_json, headersOnly(interval, limit, count), null);
			}
			if (root.has("meta") && !root.get("meta").isNull()) {
				JsonNode meta = root.get("meta");
				if (!meta.isObject()) {
					return unsupported(interval, limit, count);
				}
				if (meta.has("status") && !meta.get("status").isNull()) {
					JsonNode status = meta.get("status");
					if (!status.isTextual() || !"success".equals(status.asText())) {
						return unsupported(interval, limit, count);
					}
				}
			}
			JsonNode results = root.get("results");
			if (results == null || !results.isObject()) {
				return unsupported(interval, limit, count);
			}
			return classify(results, interval, limit, count);
		}
		catch (RuntimeException ex) {
			return PhishTankOutcome.unavailable(PhishTankDiagnostic.invalid_json, headersOnly(interval, limit, count), null);
		}
	}

	private PhishTankOutcome classify(JsonNode results, String interval, String limit, String count) {
		Flag inDatabase = flag(results, "in_database");
		if (inDatabase != Flag.TRUE && inDatabase != Flag.FALSE) {
			return unsupported(interval, limit, count);
		}
		if (inDatabase == Flag.FALSE) {
			if (present(results, "phish_id") || present(results, "phish_detail_page") || present(results, "verified") || present(results, "verified_at") || present(results, "valid")) {
				return unsupported(interval, limit, count);
			}
			return PhishTankOutcome.of(PhishTankStatus.not_listed, headersOnly(interval, limit, count));
		}
		Flag verified = flag(results, "verified");
		Flag valid = flag(results, "valid");
		if (verified == Flag.INVALID || valid == Flag.INVALID || verified == Flag.ABSENT) {
			return unsupported(interval, limit, count);
		}
		String phishId;
		String detailPage;
		Instant verifiedAt;
		try {
			phishId = optionalId(results);
			detailPage = optionalText(results, "phish_detail_page");
			verifiedAt = optionalInstant(results, "verified_at");
		}
		catch (MalformedResponse ex) {
			return unsupported(interval, limit, count);
		}
		PhishTankEvidence evidence = PhishTankEvidence.from(phishId, detailPage, verifiedAt, interval, limit, count);
		if (verified == Flag.FALSE) {
			if (valid == Flag.TRUE) {
				return unsupported(interval, limit, count);
			}
			return PhishTankOutcome.of(PhishTankStatus.listed_unverified, evidence);
		}
		if (valid == Flag.ABSENT) {
			return unsupported(interval, limit, count);
		}
		if (valid == Flag.TRUE) {
			return PhishTankOutcome.of(PhishTankStatus.verified_phishing, evidence);
		}
		return PhishTankOutcome.of(PhishTankStatus.verified_not_phishing, evidence);
	}

	private static Flag flag(JsonNode parent, String name) {
		if (!present(parent, name)) {
			return Flag.ABSENT;
		}
		JsonNode node = parent.get(name);
		if (node.isBoolean()) {
			return node.booleanValue() ? Flag.TRUE : Flag.FALSE;
		}
		if (node.isTextual()) {
			if ("y".equals(node.asText())) {
				return Flag.TRUE;
			}
			if ("n".equals(node.asText())) {
				return Flag.FALSE;
			}
		}
		return Flag.INVALID;
	}

	private static boolean present(JsonNode parent, String name) {
		return parent.has(name) && !parent.get(name).isNull();
	}

	private static String optionalId(JsonNode results) {
		if (!present(results, "phish_id")) {
			return null;
		}
		JsonNode node = results.get("phish_id");
		if (node.isTextual()) {
			String text = node.asText();
			return text.isBlank() ? null : text;
		}
		if (node.isIntegralNumber()) {
			return node.bigIntegerValue().toString();
		}
		throw new MalformedResponse();
	}

	private static String optionalText(JsonNode results, String name) {
		if (!present(results, name)) {
			return null;
		}
		JsonNode node = results.get(name);
		if (!node.isTextual()) {
			throw new MalformedResponse();
		}
		String text = node.asText();
		return text.isBlank() ? null : text;
	}

	private static Instant optionalInstant(JsonNode results, String name) {
		if (!present(results, name)) {
			return null;
		}
		JsonNode node = results.get(name);
		if (!node.isTextual() || node.asText().isBlank()) {
			throw new MalformedResponse();
		}
		try {
			return Instant.parse(node.asText());
		}
		catch (DateTimeException ex) {
			throw new MalformedResponse();
		}
	}

	private static PhishTankOutcome unsupported(String interval, String limit, String count) {
		return PhishTankOutcome.unavailable(PhishTankDiagnostic.unsupported_response, headersOnly(interval, limit, count), null);
	}

	private static PhishTankEvidence headersOnly(String interval, String limit, String count) {
		return PhishTankEvidence.from(null, null, null, interval, limit, count);
	}

	private static String header(HttpResponse<?> response, String name) {
		return response.headers().firstValue(name).map(String::trim).filter(value -> !value.isEmpty() && value.length() <= MAX_HEADER_LENGTH).orElse(null);
	}

	private String readLimited(InputStream input) throws IOException {
		try (input) {
			byte[] bytes = input.readNBytes(maxResponseBytes + 1);
			if (bytes.length > maxResponseBytes) {
				throw new ResponseTooLargeException();
			}
			return new String(bytes, StandardCharsets.UTF_8);
		}
	}

	private static void closeQuietly(InputStream input) {
		if (input == null) {
			return;
		}
		try {
			input.close();
		}
		catch (IOException ex) {
			// The HTTP status is already known. Do not retry or record the stream error.
		}
	}

	private enum Flag {
		ABSENT,
		TRUE,
		FALSE,
		INVALID
	}

	private static final class ResponseTooLargeException extends IOException {

		private static final long serialVersionUID = 1L;

		private ResponseTooLargeException() {
			super("response exceeded the size limit");
		}

	}

	private static final class MalformedResponse extends RuntimeException {

		private static final long serialVersionUID = 1L;

		private MalformedResponse() {
			super("malformed phishtank response");
		}

	}

}
