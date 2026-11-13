package com.agguidigital.phishingchecker.phishtank;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "phishtank")
public class PhishTankProperties {

	private boolean enabled;

	private String appKey = "";

	private String userAgent = PhishTankClient.DEFAULT_USER_AGENT;

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getAppKey() {
		return appKey;
	}

	public void setAppKey(String appKey) {
		this.appKey = appKey == null ? "" : appKey.trim();
	}

	public String getUserAgent() {
		return userAgent;
	}

	public void setUserAgent(String userAgent) {
		this.userAgent = userAgent == null ? "" : userAgent.trim();
	}

	public boolean hasUserAgent() {
		return !userAgent.isBlank();
	}

	@Override
	public String toString() {
		return "PhishTankProperties{enabled=" + enabled + "}";
	}

}
