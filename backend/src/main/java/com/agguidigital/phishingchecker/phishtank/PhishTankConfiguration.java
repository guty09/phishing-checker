package com.agguidigital.phishingchecker.phishtank;

import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.agguidigital.phishingchecker.virustotal.OutboundRateLimiter;

@Configuration
public class PhishTankConfiguration {

	public static final int MAX_OUTBOUND_REQUESTS = 1;

	public static final Duration RATE_WINDOW = Duration.ofSeconds(60);

	@Bean
	HttpClient phishTankHttpClient() {
		return HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(PhishTankClient.CONNECT_TIMEOUT)
				.followRedirects(HttpClient.Redirect.NEVER)
				.build();
	}

	@Bean
	OutboundRateLimiter phishTankRateLimiter(Clock clock) {
		return new OutboundRateLimiter(MAX_OUTBOUND_REQUESTS, RATE_WINDOW, clock);
	}

	@Bean
	PhishTankClient phishTankClient(@Qualifier("phishTankHttpClient") HttpClient phishTankHttpClient) {
		return new PhishTankClient(phishTankHttpClient, PhishTankClient.ENDPOINT, PhishTankClient.RESPONSE_TIMEOUT, PhishTankClient.MAX_RESPONSE_BYTES);
	}

}
