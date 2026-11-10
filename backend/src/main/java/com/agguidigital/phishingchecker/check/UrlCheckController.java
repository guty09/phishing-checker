package com.agguidigital.phishingchecker.check;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/check")
public class UrlCheckController {

	private final UrlCheckService service;

	public UrlCheckController(UrlCheckService service) {
		this.service = service;
	}

	@PostMapping("/url")
	public UrlCheckResponse check(@Valid @RequestBody UrlCheckRequest request) {
		return service.check(request.url());
	}

}
