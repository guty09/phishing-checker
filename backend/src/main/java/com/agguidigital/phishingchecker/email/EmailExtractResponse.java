package com.agguidigital.phishingchecker.email;

import java.util.List;

public record EmailExtractResponse(List<String> urls, List<String> warnings, boolean truncated) {

	public EmailExtractResponse {
		urls = List.copyOf(urls);
		warnings = List.copyOf(warnings);
	}

	@Override
	public String toString() {
		return "EmailExtractResponse{urlCount=" + urls.size() + ", truncated=" + truncated + "}";
	}

}
