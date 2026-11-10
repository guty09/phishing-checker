package com.agguidigital.phishingchecker.virustotal;

import java.time.Instant;
import java.util.Map;

import com.agguidigital.phishingchecker.check.LookupStatus;

public record VirusTotalOutcome(LookupStatus status, Instant lastAnalysisDate, Map<String, Integer> analysis) {

	public static VirusTotalOutcome of(LookupStatus status) {
		return new VirusTotalOutcome(status, null, null);
	}

	public static VirusTotalOutcome found(Instant lastAnalysisDate, Map<String, Integer> analysis) {
		return new VirusTotalOutcome(LookupStatus.found, lastAnalysisDate, Map.copyOf(analysis));
	}

}
