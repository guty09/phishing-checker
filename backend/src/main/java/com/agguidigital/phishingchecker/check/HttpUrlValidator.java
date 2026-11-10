package com.agguidigital.phishingchecker.check;

import java.net.URI;
import java.net.URISyntaxException;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class HttpUrlValidator implements ConstraintValidator<HttpUrl, String> {

	static final int MAX_LENGTH = 4096;

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		if (value == null || value.isBlank() || value.length() > MAX_LENGTH) {
			return true;
		}
		try {
			URI uri = new URI(value);
			if (!uri.isAbsolute()) {
				return false;
			}
			String scheme = uri.getScheme();
			if (scheme == null) {
				return false;
			}
			if (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) {
				return false;
			}
			String host = uri.getHost();
			return host != null && !host.isBlank();
		}
		catch (URISyntaxException ex) {
			return false;
		}
	}

}
