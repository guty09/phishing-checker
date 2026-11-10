package com.agguidigital.phishingchecker.check;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record UrlCheckRequest(
		@NotBlank(message = "url is required")
		@Size(max = HttpUrlValidator.MAX_LENGTH, message = "url is too long")
		@HttpUrl
		String url) {
}
