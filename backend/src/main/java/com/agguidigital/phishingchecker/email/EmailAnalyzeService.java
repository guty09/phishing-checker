package com.agguidigital.phishingchecker.email;

import org.springframework.stereotype.Service;

@Service
public class EmailAnalyzeService {

	public EmailAnalysisResponse analyze(String text) {
		return EmailTextAnalyzer.analyze(text);
	}

}
