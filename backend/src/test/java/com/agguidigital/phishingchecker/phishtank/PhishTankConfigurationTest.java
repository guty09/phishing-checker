package com.agguidigital.phishingchecker.phishtank;

import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PhishTankConfigurationTest {

	@Test
	void pinsTheProviderHostAndDisablesRedirects() {
		PhishTankConfiguration configuration = new PhishTankConfiguration();
		HttpClient httpClient = configuration.phishTankHttpClient();

		assertThat(httpClient.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
		assertThat(httpClient.connectTimeout()).contains(PhishTankClient.CONNECT_TIMEOUT);
		assertThat(PhishTankClient.CONNECT_TIMEOUT).isEqualTo(Duration.ofSeconds(5));
		assertThat(PhishTankClient.RESPONSE_TIMEOUT).isEqualTo(Duration.ofSeconds(10));
		assertThat(PhishTankClient.MAX_RESPONSE_BYTES).isEqualTo(1_048_576);
		assertThat(PhishTankConfiguration.MAX_OUTBOUND_REQUESTS).isEqualTo(1);
		assertThat(PhishTankConfiguration.RATE_WINDOW).isEqualTo(Duration.ofSeconds(60));

		PhishTankClient client = configuration.phishTankClient(httpClient);
		assertThat(client.endpoint()).isEqualTo(PhishTankClient.ENDPOINT);
		assertThat(client.endpoint()).isEqualTo(java.net.URI.create("https://checkurl.phishtank.com/checkurl/"));
		assertThat(PhishTankClient.allowedEndpoint(client.endpoint())).isTrue();
		assertThat(PhishTankClient.allowedEndpoint(java.net.URI.create("http://checkurl.phishtank.com/checkurl/"))).isFalse();
		assertThat(PhishTankClient.allowedEndpoint(java.net.URI.create("https://example.com/checkurl/"))).isFalse();
	}

}
