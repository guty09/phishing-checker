package com.agguidigital.phishingchecker.email;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class EmailLinkExtractorTest {

	@Test
	void extractsUrlsFromOrdinaryProse() {
		String text = """
				Hello,

				Please open https://example.com/invoices/42 today.
				The copy is also at http://files.example.com/q?id=7 if you need it.

				Thanks
				""";

		assertThat(EmailLinkExtractor.extract(text)).containsExactly(
				"https://example.com/invoices/42",
				"http://files.example.com/q?id=7");
	}

	@Test
	void deduplicatesWhilePreservingOrder() {
		String text = """
				See https://example.com/a then https://example.com/b.
				Again: https://example.com/a and https://example.com/b
				""";

		assertThat(EmailLinkExtractor.extract(text)).containsExactly(
				"https://example.com/a",
				"https://example.com/b");
	}

	@Test
	void trimsLikelyProseWrappersAroundUrls() {
		String text = """
				See (https://example.com/docs/path?q=a&b=c).
				Also <https://example.com/a/b>,
				and "https://en.wikipedia.org/wiki/URL_(disambiguation)".
				Keep https://example.com/search?q=hello,world and [https://example.com/wrapped].
				IPv6 https://[2001:db8::1]/health.
				""";

		assertThat(EmailLinkExtractor.extract(text)).containsExactly(
				"https://example.com/docs/path?q=a&b=c",
				"https://example.com/a/b",
				"https://en.wikipedia.org/wiki/URL_(disambiguation)",
				"https://example.com/search?q=hello,world",
				"https://example.com/wrapped",
				"https://[2001:db8::1]/health");
	}

	@Test
	void keepsTrailingQueryAndPathCharacters() {
		String text = """
				Is the page https://example.com/help?
				Bang https://example.com/path! and query https://example.com/search?q=hello!
				Semicolon https://example.com/a; and https://example.com/search?q=1;
				Colon https://example.com/a: and https://example.com/search?q=1:
				""";

		assertThat(EmailLinkExtractor.extract(text)).containsExactly(
				"https://example.com/help?",
				"https://example.com/path!",
				"https://example.com/search?q=hello!",
				"https://example.com/a;",
				"https://example.com/search?q=1;",
				"https://example.com/a:",
				"https://example.com/search?q=1:");
	}

	@Test
	void returnsNoUrlsWhenTextHasNoExplicitHttpLinks() {
		String text = """
				Hello, the invoice is attached to this message.
				Visit www.example.com or ftp://example.com/file.txt later.
				javascript:alert(1) is not a link we can check.
				""";

		assertThat(EmailLinkExtractor.extract(text)).isEmpty();
	}

	@Test
	void keepsEveryUniqueUrlBeforeTheResponseLimit() {
		assertThat(EmailLinkExtractor.extract(numberedUrls(21))).hasSize(21);
		assertThat(EmailLinkExtractor.extract(numberedUrls(20) + " " + "https://example.com/n/1")).hasSize(20);
	}

	private static String numberedUrls(int count) {
		StringBuilder text = new StringBuilder();
		for (int i = 1; i <= count; i++) {
			if (i > 1) {
				text.append(' ');
			}
			text.append("https://example.com/n/").append(i);
		}
		return text.toString();
	}

}
