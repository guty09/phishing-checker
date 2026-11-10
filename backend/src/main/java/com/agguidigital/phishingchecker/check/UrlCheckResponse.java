package com.agguidigital.phishingchecker.check;

import java.time.Instant;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UrlCheckResponse(
		String provider,
		LookupStatus status,
		Instant checkedAt,
		Instant lastAnalysisDate,
		Map<String, Integer> analysis) {

	public static final String PROVIDER = "virustotal";

	public static UrlCheckResponse of(LookupStatus status, Instant checkedAt) {
		return new UrlCheckResponse(PROVIDER, status, checkedAt, null, null);
	}

	public static UrlCheckResponse found(Instant checkedAt, Instant lastAnalysisDate, Map<String, Integer> analysis) {
		return new UrlCheckResponse(PROVIDER, LookupStatus.found, checkedAt, lastAnalysisDate, analysis);
	}

}
