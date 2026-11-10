package com.agguidigital.phishingchecker.email;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Finds explicit http and https URLs in plain text.
 * This scanner does not open URLs, resolve names, or parse HTML.
 *
 * Trailing {@code ?}, {@code !}, {@code ;}, and {@code :} are kept. Each is valid at the end of a
 * path or query, and plain text does not show whether it belongs to the URL or the sentence.
 * A trailing period or comma, an ellipsis, a quote, an asterisk, and an unmatched closing
 * bracket are still removed. Those are often prose, but a URL that really ends with one of them
 * is shortened. That is a boundary heuristic, not exact preservation.
 */
public final class EmailLinkExtractor {

	private static final String SIMPLE_TRAILING = ".,\"'*…";

	private EmailLinkExtractor() {
	}

	public static List<String> extract(String text) {
		Set<String> urls = new LinkedHashSet<>();
		int length = text.length();
		int index = 0;
		while (index < length) {
			int start = indexOfScheme(text, index);
			if (start < 0) {
				break;
			}
			int end = findEnd(text, start);
			String candidate = trimTrailing(text.substring(start, end));
			if (isExplicitHttpUrl(candidate)) {
				urls.add(candidate);
			}
			index = Math.max(end, start + 1);
		}
		return new ArrayList<>(urls);
	}

	private static int indexOfScheme(String text, int from) {
		for (int i = from; i < text.length(); i++) {
			if (schemeLength(text, i) > 0) {
				return i;
			}
		}
		return -1;
	}

	private static int findEnd(String text, int start) {
		int index = start + schemeLength(text, start);
		while (index < text.length()) {
			if (isBoundary(text.charAt(index)) || schemeLength(text, index) > 0) {
				return index;
			}
			index++;
		}
		return text.length();
	}

	private static int schemeLength(String text, int index) {
		if (text.regionMatches(true, index, "https://", 0, "https://".length())) {
			return "https://".length();
		}
		if (text.regionMatches(true, index, "http://", 0, "http://".length())) {
			return "http://".length();
		}
		return 0;
	}

	private static boolean isBoundary(char character) {
		return Character.isWhitespace(character)
				|| character == '<'
				|| character == '>'
				|| character == '"'
				|| character == '“'
				|| character == '”'
				|| character == '«'
				|| character == '»';
	}

	private static String trimTrailing(String value) {
		int end = value.length();
		while (end > 0 && isTrimmedTrailing(value, end)) {
			end--;
		}
		return value.substring(0, end);
	}

	private static boolean isTrimmedTrailing(String value, int end) {
		char character = value.charAt(end - 1);
		if (SIMPLE_TRAILING.indexOf(character) >= 0) {
			return true;
		}
		if (character == ')' && count(value, end, ')') > count(value, end, '(')) {
			return true;
		}
		if (character == ']' && count(value, end, ']') > count(value, end, '[')) {
			return true;
		}
		return character == '}' && count(value, end, '}') > count(value, end, '{');
	}

	private static int count(String value, int end, char target) {
		int count = 0;
		for (int i = 0; i < end; i++) {
			if (value.charAt(i) == target) {
				count++;
			}
		}
		return count;
	}

	private static boolean isExplicitHttpUrl(String value) {
		try {
			URI uri = new URI(value);
			if (!uri.isAbsolute() || uri.getScheme() == null) {
				return false;
			}
			String scheme = uri.getScheme();
			if (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https")) {
				return false;
			}
			String host = uri.getHost();
			return host != null && host.chars().anyMatch(Character::isLetterOrDigit);
		}
		catch (URISyntaxException ex) {
			return false;
		}
	}

}
