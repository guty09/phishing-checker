package com.agguidigital.phishingchecker.virustotal;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import com.agguidigital.phishingchecker.check.LookupStatus;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

public final class VirusTotalClient {

	static final URI API_ROOT = URI.create("https://www.virustotal.com");

	static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);

	static final Duration RESPONSE_TIMEOUT = Duration.ofSeconds(10);

	private static final int MAX_RESPONSE_BYTES = 1_048_576;

	private static final String REPORT_PATH = "/api/v3/urls/";

	private final HttpClient httpClient;

	private final URI apiRoot;

	private final Duration responseTimeout;

	private final ObjectMapper mapper = new ObjectMapper();

	public VirusTotalClient(HttpClient httpClient, URI apiRoot, Duration responseTimeout) {
		this.httpClient = httpClient;
		this.apiRoot = apiRoot;
		this.responseTimeout = responseTimeout;
	}

	public URI apiRoot() {
		return apiRoot;
	}

	public VirusTotalOutcome lookup(String url, String apiKey) {
		if (apiKey == null || apiKey.isBlank()) {
			return VirusTotalOutcome.of(LookupStatus.disabled);
		}
		URI requestUri = reportUri(UrlIdentifier.encode(url));
		if (requestUri == null || !sameEndpoint(requestUri)) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		HttpRequest request;
		try {
			request = HttpRequest.newBuilder(requestUri)
					.version(HttpClient.Version.HTTP_1_1)
					.timeout(responseTimeout)
					.header("Accept", "application/json")
					.header("x-apikey", apiKey)
					.GET()
					.build();
		}
		catch (IllegalArgumentException ex) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		try {
			HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
			String body = readLimited(response.body());
			return interpret(response.statusCode(), body);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		catch (IOException ex) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
	}

	private static String readLimited(InputStream input) throws IOException {
		try (input) {
			byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
			if (bytes.length > MAX_RESPONSE_BYTES) {
				throw new IOException("response exceeded the size limit");
			}
			return new String(bytes, StandardCharsets.UTF_8);
		}
	}

	private URI reportUri(String urlId) {
		try {
			return new URI(apiRoot.getScheme(), null, apiRoot.getHost(), apiRoot.getPort(), REPORT_PATH + urlId, null, null);
		}
		catch (URISyntaxException ex) {
			return null;
		}
	}

	private boolean sameEndpoint(URI requestUri) {
		return apiRoot.getScheme().equalsIgnoreCase(requestUri.getScheme())
				&& apiRoot.getHost().equalsIgnoreCase(requestUri.getHost())
				&& apiRoot.getPort() == requestUri.getPort();
	}

	private VirusTotalOutcome interpret(int status, String body) {
		if (status == 404) {
			return VirusTotalOutcome.of(LookupStatus.not_found);
		}
		if (status == 401 || status == 403) {
			return VirusTotalOutcome.of(LookupStatus.authentication_failure);
		}
		if (status == 429) {
			return VirusTotalOutcome.of(LookupStatus.rate_limited);
		}
		if (status != 200) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		return parseReport(body);
	}

	private VirusTotalOutcome parseReport(String body) {
		if (body == null || body.isBlank()) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		JsonNode root;
		try {
			root = mapper.readTree(body);
		}
		catch (RuntimeException ex) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		if (root == null || !root.isObject()) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		JsonNode attributes = root.path("data").path("attributes");
		JsonNode stats = attributes.path("last_analysis_stats");
		if (!stats.isObject()) {
			return VirusTotalOutcome.of(LookupStatus.unavailable);
		}
		Map<String, Integer> analysis = new LinkedHashMap<>();
		for (Map.Entry<String, JsonNode> field : stats.properties()) {
			JsonNode value = field.getValue();
			if (!value.isIntegralNumber() || !value.canConvertToInt()) {
				return VirusTotalOutcome.of(LookupStatus.unavailable);
			}
			analysis.put(field.getKey(), value.intValue());
		}
		Instant lastAnalysisDate = null;
		JsonNode date = attributes.get("last_analysis_date");
		if (date != null && !date.isNull()) {
			if (!date.isIntegralNumber()) {
				return VirusTotalOutcome.of(LookupStatus.unavailable);
			}
			lastAnalysisDate = Instant.ofEpochSecond(date.longValue());
		}
		return VirusTotalOutcome.found(lastAnalysisDate, analysis);
	}

}
