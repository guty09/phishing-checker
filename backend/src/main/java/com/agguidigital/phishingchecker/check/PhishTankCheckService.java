package com.agguidigital.phishingchecker.check;

import java.time.Clock;
import java.time.Instant;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.agguidigital.phishingchecker.phishtank.PhishTankClient;
import com.agguidigital.phishingchecker.phishtank.PhishTankOutcome;
import com.agguidigital.phishingchecker.phishtank.PhishTankProperties;
import com.agguidigital.phishingchecker.virustotal.OutboundRateLimiter;

@Service
public class PhishTankCheckService {

	private final PhishTankProperties properties;

	private final PhishTankClient client;

	private final OutboundRateLimiter rateLimiter;

	private final Clock clock;

	public PhishTankCheckService(PhishTankProperties properties, PhishTankClient client, @Qualifier("phishTankRateLimiter") OutboundRateLimiter rateLimiter, Clock clock) {
		this.properties = properties;
		this.client = client;
		this.rateLimiter = rateLimiter;
		this.clock = clock;
	}

	public PhishTankCheckResponse check(String url) {
		Instant checkedAt = clock.instant();
		if (!properties.isEnabled()) {
			return PhishTankCheckResponse.of(PhishTankStatus.disabled, checkedAt);
		}
		if (!properties.hasUserAgent()) {
			return PhishTankCheckResponse.of(PhishTankStatus.unavailable, checkedAt);
		}
		if (!rateLimiter.tryAcquire()) {
			return PhishTankCheckResponse.of(PhishTankStatus.rate_limited, checkedAt);
		}
		PhishTankOutcome outcome = client.lookup(url, properties.getAppKey(), properties.getUserAgent());
		return PhishTankCheckResponse.of(outcome.status(), checkedAt, outcome.evidence(), outcome.diagnostic(), outcome.providerStatus());
	}

}
