package com.agguidigital.phishingchecker.email;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class EmailExtractService {

	static final int MAX_URLS = 20;

	static final String HEADERS_WARNING = "Pasted text does not include full email headers.";

	static final String HTML_WARNING = "Pasted text can hide the original HTML link destination.";

	static final String TRUNCATION_WARNING = "More than 20 unique URLs were found. Only the first 20 are returned.";

	public EmailExtractResponse extract(String text) {
		List<String> extracted = EmailLinkExtractor.extract(text);
		boolean truncated = extracted.size() > MAX_URLS;
		List<String> urls = truncated ? extracted.subList(0, MAX_URLS) : extracted;
		List<String> warnings = new ArrayList<>();
		warnings.add(HEADERS_WARNING);
		warnings.add(HTML_WARNING);
		if (truncated) {
			warnings.add(TRUNCATION_WARNING);
		}
		return new EmailExtractResponse(urls, warnings, truncated);
	}

}
