package com.agguidigital.phishingchecker.email;

import java.util.List;

public record EmailAnalysisResponse(
		EmailAssessment assessment,
		List<EmailFinding> findings,
		List<String> limitations) {

	public EmailAnalysisResponse {
		findings = List.copyOf(findings);
		limitations = List.copyOf(limitations);
	}

	@Override
	public String toString() {
		return "EmailAnalysisResponse{assessment=" + assessment + ", findingCount=" + findings.size() + "}";
	}

}
