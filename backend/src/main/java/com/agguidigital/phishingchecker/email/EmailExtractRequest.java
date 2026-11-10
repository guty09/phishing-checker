package com.agguidigital.phishingchecker.email;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailExtractRequest(
		@NotBlank(message = "text is required")
		@Size(max = EmailExtractRequest.MAX_LENGTH, message = "text is too long")
		String text) {

	public static final int MAX_LENGTH = 50_000;

	@Override
	public String toString() {
		return "EmailExtractRequest{length=" + (text == null ? 0 : text.length()) + "}";
	}

}
