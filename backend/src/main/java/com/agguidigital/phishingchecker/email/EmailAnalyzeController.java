package com.agguidigital.phishingchecker.email;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/email")
public class EmailAnalyzeController {

	private final EmailAnalyzeService service;

	public EmailAnalyzeController(EmailAnalyzeService service) {
		this.service = service;
	}

	@PostMapping("/analyze")
	public EmailAnalysisResponse analyze(@Valid @RequestBody EmailExtractRequest request) {
		return service.analyze(request.text());
	}

}
