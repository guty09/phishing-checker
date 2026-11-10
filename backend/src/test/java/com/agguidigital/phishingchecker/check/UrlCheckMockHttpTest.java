package com.agguidigital.phishingchecker.check;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import com.agguidigital.phishingchecker.support.MockVirusTotalServer;
import com.agguidigital.phishingchecker.support.MockVirusTotalServer.RecordedRequest;
import com.agguidigital.phishingchecker.support.MutableClock;
import com.agguidigital.phishingchecker.virustotal.OutboundRateLimiter;
import com.agguidigital.phishingchecker.virustotal.VirusTotalClient;
import com.agguidigital.phishingchecker.virustotal.VirusTotalProperties;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class UrlCheckMockHttpTest {

	private static final String DUMMY_KEY = "vt-test-key";

	private static final Instant CHECKED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String URL = "https://example.com";

	private MockVirusTotalServer server;

	private VirusTotalProperties properties;

	private MockMvc mockMvc;

	private final ObjectMapper json = new ObjectMapper();

	@BeforeEach
	void setUp() throws Exception {
		server = new MockVirusTotalServer();
		properties = new VirusTotalProperties();
		properties.setApiKey(DUMMY_KEY);
		HttpClient httpClient = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(Duration.ofSeconds(2))
				.followRedirects(HttpClient.Redirect.NEVER)
				.build();
		VirusTotalClient client = new VirusTotalClient(httpClient, server.root(), Duration.ofMillis(300));
		OutboundRateLimiter limiter = new OutboundRateLimiter(4, Duration.ofSeconds(60), new MutableClock(CHECKED_AT));
		UrlCheckService service = new UrlCheckService(properties, client, limiter, new MutableClock(CHECKED_AT));
		LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
		validator.afterPropertiesSet();
		mockMvc = MockMvcBuilders.standaloneSetup(new UrlCheckController(service))
				.setControllerAdvice(new ApiExceptionHandler())
				.setValidator(validator)
				.setMessageConverters(new JacksonJsonHttpMessageConverter())
				.build();
	}

	@AfterEach
	void tearDown() {
		server.close();
	}

	@Test
	void successReturnsNormalizedReportWithoutSendingTheUrlToScan() throws Exception {
		server.respond(200, """
				{"data":{"type":"url","attributes":{
				  "url":"https://example.com",
				  "last_analysis_date":1591715484,
				  "last_analysis_stats":{"harmless":70,"malicious":2,"suspicious":1,"undetected":9,"timeout":0},
				  "last_analysis_results":{"Engine":{"result":"clean"}}
				}}}
				""");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.provider").value("virustotal"))
				.andExpect(jsonPath("$.status").value("found"))
				.andExpect(jsonPath("$.checkedAt").value("2026-01-01T00:00:00Z"))
				.andExpect(jsonPath("$.lastAnalysisDate").value("2020-06-09T15:11:24Z"))
				.andExpect(jsonPath("$.analysis.harmless").value(70))
				.andExpect(jsonPath("$.analysis.malicious").value(2))
				.andExpect(jsonPath("$.analysis.suspicious").value(1))
				.andExpect(jsonPath("$.analysis.undetected").value(9))
				.andExpect(jsonPath("$.analysis.timeout").value(0))
				.andExpect(jsonPath("$.analysis.Engine").doesNotExist());

		assertThat(server.requests()).hasSize(1);
		RecordedRequest request = server.requests().get(0);
		assertThat(request.method()).isEqualTo("GET");
		assertThat(request.query()).isNull();
		assertThat(request.path()).isEqualTo("/api/v3/urls/" + unpaddedUrlId(URL));
		assertThat(request.dummyApiKey()).isTrue();
		assertThat(server.followedRedirects()).isZero();
		assertThat(server.root().getHost()).isEqualTo("127.0.0.1");
	}

	@Test
	void missingKeyDoesNotCallTheProvider() throws Exception {
		properties.setApiKey(null);
		server.respond(200, "{}");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("disabled"))
				.andExpect(jsonPath("$.provider").value("virustotal"))
				.andExpect(jsonPath("$.lastAnalysisDate").doesNotExist())
				.andExpect(jsonPath("$.analysis").doesNotExist());

		assertThat(server.requests()).isEmpty();
	}

	@Test
	void blankKeyDoesNotCallTheProvider() throws Exception {
		properties.setApiKey("   ");
		server.respond(200, "{}");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("disabled"));

		assertThat(server.requests()).isEmpty();
	}

	@Test
	void notFoundIsNotTreatedAsSafe() throws Exception {
		server.respond(404, "{\"error\":{\"code\":\"NotFoundError\"}}");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("not_found"))
				.andExpect(jsonPath("$.analysis").doesNotExist());

		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void authenticationFailureCoversUnauthorizedAndForbidden() throws Exception {
		server.respond(401, "{\"error\":\"unauthorized\"}");
		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(jsonPath("$.status").value("authentication_failure"));

		server.resetRequests();
		server.respond(403, "{\"error\":\"forbidden\"}");
		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body("http://example.com")))
				.andExpect(jsonPath("$.status").value("authentication_failure"));

		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void providerRateLimitIsReported() throws Exception {
		server.respond(429, "{\"error\":\"QuotaExceeded\"}");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(jsonPath("$.status").value("rate_limited"));

		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void timeoutIsUnavailableAndIsNotRetried() throws Exception {
		server.delay(Duration.ofSeconds(2));

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(jsonPath("$.status").value("unavailable"));

		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void malformedProviderResponsesAreUnavailable() throws Exception {
		assertMalformed("{not-json");
		assertMalformed("{\"data\":{\"attributes\":{}}}");
		assertMalformed("{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":\"yes\"}}}}");
		assertMalformed("{\"data\":{\"attributes\":{\"last_analysis_date\":\"yesterday\",\"last_analysis_stats\":{\"malicious\":1}}}}");
	}

	@Test
	void redirectFromTheProviderIsNotFollowed() throws Exception {
		server.respond(302, "");

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(jsonPath("$.status").value("unavailable"));

		assertThat(server.requests()).hasSize(1);
		assertThat(server.followedRedirects()).isZero();
	}

	@Test
	void localLimitStopsOutboundCallsAfterFourInTheWindow() throws Exception {
		server.respond(404, "");

		for (int i = 0; i < 4; i++) {
			mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
					.andExpect(jsonPath("$.status").value("not_found"));
		}
		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(jsonPath("$.status").value("rate_limited"));

		assertThat(server.requests()).hasSize(4);
	}

	@Test
	void rejectsInvalidUrlsBeforeCallingTheProvider() throws Exception {
		assertInvalid("ftp://example.com/not-fetched");
		assertInvalid("example.com");
		assertInvalid("javascript:alert(1)");
		assertInvalid("http://");
		assertInvalid("   ");
		assertInvalid("a".repeat(HttpUrlValidator.MAX_LENGTH + 1));

		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content("{}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_url"));
		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content("{"))
				.andExpect(status().isBadRequest());

		assertThat(server.requests()).isEmpty();
	}

	private void assertMalformed(String providerBody) throws Exception {
		server.resetRequests();
		server.respond(200, providerBody);
		mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.analysis").doesNotExist());
		assertThat(server.requests()).hasSize(1);
	}

	private void assertInvalid(String url) throws Exception {
		String response = mockMvc.perform(post("/api/check/url").contentType(MediaType.APPLICATION_JSON).content(body(url)))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_url"))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("not-fetched");
	}

	private String body(String url) throws Exception {
		return json.writeValueAsString(new UrlCheckRequest(url));
	}

	private static String unpaddedUrlId(String url) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes(StandardCharsets.UTF_8));
	}

}
