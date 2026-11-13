package com.agguidigital.phishingchecker.check;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record PhishTankEvidence(
		String phishId,
		String phishDetailPage,
		Instant verifiedAt,
		String requestLimitInterval,
		String requestLimit,
		String requestCount) {

	public static PhishTankEvidence from(
			String phishId,
			String phishDetailPage,
			Instant verifiedAt,
			String requestLimitInterval,
			String requestLimit,
			String requestCount) {
		if (phishId == null && phishDetailPage == null && verifiedAt == null && requestLimitInterval == null && requestLimit == null && requestCount == null) {
			return null;
		}
		return new PhishTankEvidence(phishId, phishDetailPage, verifiedAt, requestLimitInterval, requestLimit, requestCount);
	}

}
