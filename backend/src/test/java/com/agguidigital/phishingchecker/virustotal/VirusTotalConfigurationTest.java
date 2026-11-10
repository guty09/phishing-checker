package com.agguidigital.phishingchecker.virustotal;

import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VirusTotalConfigurationTest {

	@Test
	void keepsTheApiHostFixedAndDisablesRedirects() {
		VirusTotalConfiguration configuration = new VirusTotalConfiguration();
		HttpClient httpClient = configuration.virusTotalHttpClient();

		assertThat(httpClient.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
		assertThat(httpClient.connectTimeout()).contains(VirusTotalClient.CONNECT_TIMEOUT);
		assertThat(httpClient.connectTimeout().orElseThrow()).isLessThan(Duration.ofSeconds(30));

		VirusTotalClient client = configuration.virusTotalClient(httpClient);
		assertThat(client.apiRoot()).isEqualTo(URI.create("https://www.virustotal.com"));
	}

}
