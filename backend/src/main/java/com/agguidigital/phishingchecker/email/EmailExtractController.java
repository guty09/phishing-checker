package com.agguidigital.phishingchecker.email;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/email")
public class EmailExtractController {

	private final EmailExtractService service;

	public EmailExtractController(EmailExtractService service) {
		this.service = service;
	}

	@PostMapping("/extract")
	public EmailExtractResponse extract(@Valid @RequestBody EmailExtractRequest request) {
		return service.extract(request.text());
	}

}
