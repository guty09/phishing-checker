package com.agguidigital.phishingchecker.check;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/check")
public class PhishTankCheckController {

	private final PhishTankCheckService service;

	public PhishTankCheckController(PhishTankCheckService service) {
		this.service = service;
	}

	@PostMapping("/url/phishtank")
	public PhishTankCheckResponse check(@Valid @RequestBody UrlCheckRequest request) {
		return service.check(request.url());
	}

}
