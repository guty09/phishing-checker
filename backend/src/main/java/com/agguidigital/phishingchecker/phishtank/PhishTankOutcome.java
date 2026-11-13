package com.agguidigital.phishingchecker.phishtank;

import com.agguidigital.phishingchecker.check.PhishTankDiagnostic;
import com.agguidigital.phishingchecker.check.PhishTankEvidence;
import com.agguidigital.phishingchecker.check.PhishTankStatus;

public record PhishTankOutcome(PhishTankStatus status, PhishTankEvidence evidence, PhishTankDiagnostic diagnostic, Integer providerStatus) {

	public static PhishTankOutcome of(PhishTankStatus status) {
		return new PhishTankOutcome(status, null, null, null);
	}

	public static PhishTankOutcome of(PhishTankStatus status, PhishTankEvidence evidence) {
		return new PhishTankOutcome(status, evidence, null, null);
	}

	public static PhishTankOutcome unavailable(PhishTankDiagnostic diagnostic) {
		return new PhishTankOutcome(PhishTankStatus.unavailable, null, diagnostic, null);
	}

	public static PhishTankOutcome unavailable(PhishTankDiagnostic diagnostic, PhishTankEvidence evidence, Integer providerStatus) {
		return new PhishTankOutcome(PhishTankStatus.unavailable, evidence, diagnostic, providerStatus);
	}

}
