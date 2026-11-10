package com.agguidigital.phishingchecker.virustotal;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class VirusTotalConfiguration {

	static final int MAX_OUTBOUND_REQUESTS = 4;

	static final Duration RATE_WINDOW = Duration.ofSeconds(60);

	@Bean
	Clock clock() {
		return Clock.systemUTC();
	}

	@Bean
	HttpClient virusTotalHttpClient() {
		return HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(VirusTotalClient.CONNECT_TIMEOUT)
				.followRedirects(HttpClient.Redirect.NEVER)
				.build();
	}

	@Bean
	OutboundRateLimiter virusTotalRateLimiter(Clock clock) {
		return new OutboundRateLimiter(MAX_OUTBOUND_REQUESTS, RATE_WINDOW, clock);
	}

	@Bean
	VirusTotalClient virusTotalClient(HttpClient virusTotalHttpClient) {
		return new VirusTotalClient(virusTotalHttpClient, VirusTotalClient.API_ROOT, VirusTotalClient.RESPONSE_TIMEOUT);
	}

}
