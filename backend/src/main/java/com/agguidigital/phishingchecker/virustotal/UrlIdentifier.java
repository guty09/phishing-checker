package com.agguidigital.phishingchecker.virustotal;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * VirusTotal URL identifier: unpadded URL-safe Base64 of the raw URL, as documented
 * for {@code GET /api/v3/urls/{id}}. The URL is not canonicalized and is not fetched.
 */
public final class UrlIdentifier {

	private UrlIdentifier() {
	}

	public static String encode(String url) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(url.getBytes(StandardCharsets.UTF_8));
	}

}
