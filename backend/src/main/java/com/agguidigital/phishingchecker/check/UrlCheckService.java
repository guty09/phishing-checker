package com.agguidigital.phishingchecker.check;

import java.time.Clock;
import java.time.Instant;

import org.springframework.stereotype.Service;

import com.agguidigital.phishingchecker.virustotal.OutboundRateLimiter;
import com.agguidigital.phishingchecker.virustotal.VirusTotalClient;
import com.agguidigital.phishingchecker.virustotal.VirusTotalOutcome;
import com.agguidigital.phishingchecker.virustotal.VirusTotalProperties;

@Service
public class UrlCheckService {

	private final VirusTotalProperties properties;

	private final VirusTotalClient client;

	private final OutboundRateLimiter rateLimiter;

	private final Clock clock;

	public UrlCheckService(VirusTotalProperties properties, VirusTotalClient client, OutboundRateLimiter rateLimiter, Clock clock) {
		this.properties = properties;
		this.client = client;
		this.rateLimiter = rateLimiter;
		this.clock = clock;
	}

	public UrlCheckResponse check(String url) {
		Instant checkedAt = clock.instant();
		if (!properties.isEnabled()) {
			return UrlCheckResponse.of(LookupStatus.disabled, checkedAt);
		}
		if (!rateLimiter.tryAcquire()) {
			return UrlCheckResponse.of(LookupStatus.rate_limited, checkedAt);
		}
		VirusTotalOutcome outcome = client.lookup(url, properties.getApiKey());
		if (outcome.status() == LookupStatus.found) {
			return UrlCheckResponse.found(checkedAt, outcome.lastAnalysisDate(), outcome.analysis());
		}
		return UrlCheckResponse.of(outcome.status(), checkedAt);
	}

}
