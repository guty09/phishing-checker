package com.agguidigital.phishingchecker.virustotal;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "virustotal")
public class VirusTotalProperties {

	private String apiKey = "";

	public String getApiKey() {
		return apiKey;
	}

	public void setApiKey(String apiKey) {
		this.apiKey = apiKey == null ? "" : apiKey.trim();
	}

	public boolean isEnabled() {
		return !apiKey.isBlank();
	}

	@Override
	public String toString() {
		return "VirusTotalProperties{enabled=" + isEnabled() + "}";
	}

}
