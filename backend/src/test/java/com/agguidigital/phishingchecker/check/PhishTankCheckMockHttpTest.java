package com.agguidigital.phishingchecker.check;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;

import com.agguidigital.phishingchecker.phishtank.PhishTankClient;
import com.agguidigital.phishingchecker.phishtank.PhishTankConfiguration;
import com.agguidigital.phishingchecker.phishtank.PhishTankProperties;
import com.agguidigital.phishingchecker.support.MockPhishTankServer;
import com.agguidigital.phishingchecker.support.MockPhishTankServer.RecordedRequest;
import com.agguidigital.phishingchecker.support.MutableClock;
import com.agguidigital.phishingchecker.virustotal.OutboundRateLimiter;

import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PhishTankCheckMockHttpTest {

	private static final String DUMMY_KEY = "pt-test-key";

	private static final String USER_AGENT = "phishing-checker test";

	private static final Instant CHECKED_AT = Instant.parse("2026-01-01T00:00:00Z");

	private static final String URL = "https://example.com/a?x=1&y=2";

	private MockPhishTankServer server;

	private PhishTankProperties properties;

	private MutableClock clock;

	private HttpClient httpClient;

	private MockMvc mockMvc;

	private final ObjectMapper json = new ObjectMapper();

	@BeforeEach
	void setUp() throws Exception {
		server = new MockPhishTankServer();
		properties = new PhishTankProperties();
		properties.setEnabled(true);
		properties.setAppKey(DUMMY_KEY);
		properties.setUserAgent(USER_AGENT);
		clock = new MutableClock(CHECKED_AT);
		httpClient = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(Duration.ofSeconds(2))
				.followRedirects(HttpClient.Redirect.NEVER)
				.build();
		PhishTankClient client = new PhishTankClient(httpClient, server.endpoint(), Duration.ofSeconds(2), PhishTankClient.MAX_RESPONSE_BYTES);
		OutboundRateLimiter limiter = new OutboundRateLimiter(PhishTankConfiguration.MAX_OUTBOUND_REQUESTS, PhishTankConfiguration.RATE_WINDOW, clock);
		PhishTankCheckService service = new PhishTankCheckService(properties, client, limiter, clock);
		LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
		validator.afterPropertiesSet();
		mockMvc = MockMvcBuilders.standaloneSetup(new PhishTankCheckController(service))
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
	void encodesTheFormAndParsesStringFlagsAsVerifiedPhishing() throws Exception {
		server.respond(200, results("""
				"in_database":"y","phish_id":"42","phish_detail_page":"https://phishtank.org/phish_detail.php?phish_id=42","verified":"y","verified_at":"2024-05-01T12:30:00Z","valid":"y"
				"""));

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body(URL)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.provider").value("phishtank"))
				.andExpect(jsonPath("$.status").value("verified_phishing"))
				.andExpect(jsonPath("$.checkedAt").value("2026-01-01T00:00:00Z"))
				.andExpect(jsonPath("$.evidence.phishId").value("42"))
				.andExpect(jsonPath("$.evidence.phishDetailPage").value("https://phishtank.org/phish_detail.php?phish_id=42"))
				.andExpect(jsonPath("$.evidence.verifiedAt").value("2024-05-01T12:30:00Z"))
				.andExpect(jsonPath("$.limitations[0]").value("Not listed does not mean the URL is safe."))
				.andExpect(jsonPath("$.limitations[1]").value("Verified not phishing does not mean the URL is safe."))
				.andExpect(jsonPath("$.safe").doesNotExist());

		assertThat(server.requests()).hasSize(1);
		RecordedRequest request = server.requests().get(0);
		assertThat(request.method()).isEqualTo("POST");
		assertThat(request.path()).isEqualTo("/checkurl/");
		assertThat(request.query()).isNull();
		assertThat(request.contentType()).startsWith("application/x-www-form-urlencoded");
		assertThat(request.userAgent()).isEqualTo(USER_AGENT);
		assertThat(request.body()).isEqualTo("url=" + URLEncoder.encode(URL, StandardCharsets.UTF_8) + "&format=json&app_key=" + URLEncoder.encode(DUMMY_KEY, StandardCharsets.UTF_8));
		assertThat(request.body()).doesNotContain("&y=2");
		assertThat(server.followedRedirects()).isZero();
	}

	@Test
	void parsesBooleanFlagsAndOmitsAMissingTimestamp() throws Exception {
		server.respond(200, results("""
				"in_database":true,"phish_id":42,"verified":true,"valid":true
				"""));

		String response = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/UNIQUE-URL-MARKER")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("verified_phishing"))
				.andExpect(jsonPath("$.evidence.phishId").value("42"))
				.andExpect(jsonPath("$.evidence.verifiedAt").doesNotExist())
				.andExpect(jsonPath("$.evidence.phishDetailPage").doesNotExist())
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(response).doesNotContain("UNIQUE-URL-MARKER").doesNotContain(DUMMY_KEY);
		assertThat(server.requests()).hasSize(1);
		assertThat(server.requests().get(0).body()).endsWith("&format=json&app_key=" + DUMMY_KEY);
	}

	@Test
	void omitsTheApplicationKeyWhenItIsBlank() throws Exception {
		properties.setAppKey("  ");
		server.respond(200, results("\"in_database\":false"));

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com")))
				.andExpect(jsonPath("$.status").value("not_listed"))
				.andExpect(jsonPath("$.evidence").doesNotExist());

		assertThat(server.requests()).hasSize(1);
		assertThat(server.requests().get(0).body()).isEqualTo("url=" + URLEncoder.encode("https://example.com", StandardCharsets.UTF_8) + "&format=json");
		assertThat(server.requests().get(0).body()).doesNotContain("app_key");
	}

	@Test
	void notListedAndUnverifiedAndInvalidPhishStayDistinct() throws Exception {
		server.respond(200, results("\"in_database\":\"n\""));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/listed-none")))
				.andExpect(jsonPath("$.status").value("not_listed"))
				.andExpect(jsonPath("$.evidence").doesNotExist());

		clock.plus(Duration.ofSeconds(60));
		server.respond(200, results("\"in_database\":true,\"verified\":false,\"valid\":\"n\",\"phish_id\":\"7\""));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/listed-open")))
				.andExpect(jsonPath("$.status").value("listed_unverified"))
				.andExpect(jsonPath("$.evidence.phishId").value("7"))
				.andExpect(jsonPath("$.evidence.verifiedAt").doesNotExist());

		clock.plus(Duration.ofSeconds(60));
		server.respond(200, results("\"in_database\":true,\"verified\":\"y\",\"valid\":false,\"phish_id\":\"8\""));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/listed-invalid")))
				.andExpect(jsonPath("$.status").value("verified_not_phishing"))
				.andExpect(jsonPath("$.evidence.phishId").value("8"));

		assertThat(server.requests()).hasSize(3);
	}

	@Test
	void malformedOrContradictoryFieldsAreUnavailable() throws Exception {
		assertUnavailable(results("\"in_database\":\"true\""), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable(results("\"in_database\":true,\"verified\":\"Y\",\"valid\":\"y\""), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable(results("\"in_database\":true,\"verified\":\"y\""), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable(results("\"in_database\":false,\"phish_id\":\"9\""), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable(results("\"in_database\":true,\"verified\":false,\"valid\":true"), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable(results("\"in_database\":true,\"verified\":\"y\",\"valid\":\"y\",\"verified_at\":\"yesterday\""), "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable("{\"meta\":{\"status\":\"error\"},\"results\":{\"in_database\":false}}", "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable("{\"meta\":{\"status\":\"success\"}}", "unsupported_response");
		clock.plus(Duration.ofSeconds(60));
		assertUnavailable("not-json", "invalid_json");
		assertThat(server.requests()).hasSize(9);
	}

	@Test
	void http509IsRateLimitedAndIsNotRetried() throws Exception {
		server.respond(509, results("\"in_database\":false"), Map.of(
				"X-Request-Limit-Interval", "300",
				"X-Request-Limit", "10",
				"X-Request-Count", "10"));

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/limited")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("rate_limited"))
				.andExpect(jsonPath("$.diagnostic").doesNotExist())
				.andExpect(jsonPath("$.evidence.requestLimitInterval").value("300"))
				.andExpect(jsonPath("$.evidence.requestLimit").value("10"))
				.andExpect(jsonPath("$.evidence.requestCount").value("10"))
				.andExpect(jsonPath("$.evidence.phishId").doesNotExist());

		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void otherProviderErrorsAreUnavailable() throws Exception {
		server.respond(429, results("\"in_database\":false"));

		String response = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/other")))
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").value("provider_http_status"))
				.andExpect(jsonPath("$.providerStatus").value(429))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("in_database");

		assertThat(server.requests()).hasSize(1);
		assertThat(server.followedRedirects()).isZero();
	}

	@Test
	void redirectIsNotFollowed() throws Exception {
		server.respond(302, "");

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/redirect")))
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").value("provider_http_status"))
				.andExpect(jsonPath("$.providerStatus").value(302));

		assertThat(server.requests()).hasSize(1);
		assertThat(server.followedRedirects()).isZero();
	}

	@Test
	void disabledConfigurationDoesNotCallTheProviderOrConsumeTheLimiter() throws Exception {
		properties.setEnabled(false);
		server.respond(200, results("\"in_database\":false"));

		String response = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/disabled")))
				.andExpect(jsonPath("$.status").value("disabled"))
				.andExpect(jsonPath("$.provider").value("phishtank"))
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(response).doesNotContain(DUMMY_KEY);
		assertThat(server.requests()).isEmpty();

		properties.setEnabled(true);
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/after")))
				.andExpect(jsonPath("$.status").value("not_listed"));
		assertThat(server.requests()).hasSize(1);
	}

	@Test
	void blankUserAgentDoesNotCallTheProvider() throws Exception {
		properties.setUserAgent(" ");
		server.respond(200, results("\"in_database\":false"));

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/no-agent")))
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").doesNotExist());

		assertThat(server.requests()).isEmpty();
	}

	@Test
	void localLimiterAllowsOneOutboundRequestPerRollingMinute() throws Exception {
		server.respond(200, results("\"in_database\":false"));

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/one")))
				.andExpect(jsonPath("$.status").value("not_listed"));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/two")))
				.andExpect(jsonPath("$.status").value("rate_limited"))
				.andExpect(jsonPath("$.evidence").doesNotExist());

		clock.plus(Duration.ofSeconds(59));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/three")))
				.andExpect(jsonPath("$.status").value("rate_limited"));
		assertThat(server.requests()).hasSize(1);

		clock.plus(Duration.ofSeconds(1));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/four")))
				.andExpect(jsonPath("$.status").value("not_listed"))
				.andExpect(jsonPath("$.checkedAt").value("2026-01-01T00:01:00Z"));
		assertThat(server.requests()).hasSize(2);
	}

	@Test
	void validationRejectsTheUrlBeforeAnyProviderCall() throws Exception {
		server.respond(200, results("\"in_database\":false"));

		String response = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content("{\"url\":\"ftp://example.com/UNIQUE-URL-MARKER\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_url"))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("UNIQUE-URL-MARKER");

		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content("{\"url\":\"\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_url"));
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content("{}"))
				.andExpect(status().isBadRequest());
		mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content("{"))
				.andExpect(status().isBadRequest());
		String longUrl = "https://example.com/" + "a".repeat(4080);
		String longResponse = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body(longUrl)))
				.andExpect(status().isBadRequest())
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(longResponse).doesNotContain(longUrl);

		assertThat(server.requests()).isEmpty();
	}

	@Test
	void oversizedOrSlowResponsesAreUnavailableWithoutARetry() throws Exception {
		PhishTankClient small = new PhishTankClient(httpClient, server.endpoint(), Duration.ofMillis(200), 8);
		OutboundRateLimiter limiter = new OutboundRateLimiter(1, Duration.ofSeconds(60), clock);
		MockMvc smallMvc = mockMvc(new PhishTankCheckService(properties, small, limiter, clock));
		server.respond(200, "x".repeat(32));

		smallMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/big")))
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").value("oversized_response"))
				.andExpect(jsonPath("$.providerStatus").doesNotExist());
		assertThat(server.requests()).hasSize(1);

		clock.plus(Duration.ofSeconds(60));
		PhishTankClient impatient = new PhishTankClient(httpClient, server.endpoint(), Duration.ofMillis(200), PhishTankClient.MAX_RESPONSE_BYTES);
		MockMvc impatientMvc = mockMvc(new PhishTankCheckService(properties, impatient, new OutboundRateLimiter(1, Duration.ofSeconds(60), clock), clock));
		server.delay(Duration.ofSeconds(2));
		impatientMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/slow")))
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").value("timeout"))
				.andExpect(jsonPath("$.providerStatus").doesNotExist());
		assertThat(server.requests()).hasSize(2);
	}

	private void assertUnavailable(String payload, String diagnostic) throws Exception {
		server.respond(200, payload);
		String response = mockMvc.perform(post("/api/check/url/phishtank").contentType(MediaType.APPLICATION_JSON).content(body("https://example.com/bad")))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.status").value("unavailable"))
				.andExpect(jsonPath("$.diagnostic").value(diagnostic))
				.andExpect(jsonPath("$.providerStatus").doesNotExist())
				.andExpect(jsonPath("$.evidence.phishId").doesNotExist())
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("https://example.com/bad");
	}

	private MockMvc mockMvc(PhishTankCheckService service) {
		LocalValidatorFactoryBean validator = new LocalValidatorFactoryBean();
		validator.afterPropertiesSet();
		return MockMvcBuilders.standaloneSetup(new PhishTankCheckController(service))
				.setControllerAdvice(new ApiExceptionHandler())
				.setValidator(validator)
				.setMessageConverters(new JacksonJsonHttpMessageConverter())
				.build();
	}

	private static String results(String fields) {
		return "{\"meta\":{\"status\":\"success\"},\"results\":{" + fields + "}}";
	}

	private String body(String url) throws Exception {
		return json.writeValueAsString(new UrlCheckRequest(url));
	}

}
