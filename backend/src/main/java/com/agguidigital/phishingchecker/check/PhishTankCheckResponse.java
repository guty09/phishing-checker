package com.agguidigital.phishingchecker.check;

import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record PhishTankCheckResponse(
		String provider,
		PhishTankStatus status,
		Instant checkedAt,
		PhishTankEvidence evidence,
		List<String> limitations,
		PhishTankDiagnostic diagnostic,
		Integer providerStatus) {

	public static final String PROVIDER = "phishtank";

	public static final List<String> LIMITATIONS = List.of(
			"Not listed does not mean the URL is safe.",
			"Verified not phishing does not mean the URL is safe.",
			"This lookup sends the submitted URL to PhishTank. It does not open that URL or submit a phishing report.",
			"A missing, malformed, or contradictory PhishTank field is unavailable rather than a safety verdict.");

	public PhishTankCheckResponse {
		limitations = List.copyOf(limitations);
	}

	public static PhishTankCheckResponse of(PhishTankStatus status, Instant checkedAt) {
		return of(status, checkedAt, null);
	}

	public static PhishTankCheckResponse of(PhishTankStatus status, Instant checkedAt, PhishTankEvidence evidence) {
		return of(status, checkedAt, evidence, null, null);
	}

	public static PhishTankCheckResponse of(PhishTankStatus status, Instant checkedAt, PhishTankEvidence evidence, PhishTankDiagnostic diagnostic, Integer providerStatus) {
		return new PhishTankCheckResponse(PROVIDER, status, checkedAt, evidence, LIMITATIONS, diagnostic, providerStatus);
	}

}
