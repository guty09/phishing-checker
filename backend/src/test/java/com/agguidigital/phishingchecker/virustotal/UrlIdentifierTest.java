package com.agguidigital.phishingchecker.virustotal;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class UrlIdentifierTest {

	@Test
	void encodesTheDocumentedUnpaddedUrlSafeBase64Identifier() {
		assertThat(UrlIdentifier.encode("http://www.somedomain.com/this/is/my/url"))
				.isEqualTo("aHR0cDovL3d3dy5zb21lZG9tYWluLmNvbS90aGlzL2lzL215L3VybA");
	}

}
