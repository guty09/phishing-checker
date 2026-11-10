package com.agguidigital.phishingchecker.email;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "virustotal.api-key=")
@AutoConfigureMockMvc
class EmailExtractControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void returnsUrlsAndWarningsForOrdinaryProse() throws Exception {
		String text = """
				Hello,

				Please review https://example.com/invoices/42.
				Bare example.com and ftp://example.com/file.txt are not explicit HTTP links.
				""";

		mockMvc.perform(post("/api/email/extract")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body(text)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.urls.length()").value(1))
				.andExpect(jsonPath("$.urls[0]").value("https://example.com/invoices/42"))
				.andExpect(jsonPath("$.truncated").value(false))
				.andExpect(jsonPath("$.warnings.length()").value(2))
				.andExpect(jsonPath("$.warnings[0]").value(EmailExtractService.HEADERS_WARNING))
				.andExpect(jsonPath("$.warnings[1]").value(EmailExtractService.HTML_WARNING));
	}

	@Test
	void reportsTruncationAfterTwentyUniqueUrls() throws Exception {
		String response = mockMvc.perform(post("/api/email/extract")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body(numberedUrls(21))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.truncated").value(true))
				.andExpect(jsonPath("$.urls.length()").value(20))
				.andExpect(jsonPath("$.urls[0]").value("https://example.com/n/1"))
				.andExpect(jsonPath("$.urls[19]").value("https://example.com/n/20"))
				.andExpect(jsonPath("$.warnings.length()").value(3))
				.andExpect(jsonPath("$.warnings[0]").value(EmailExtractService.HEADERS_WARNING))
				.andExpect(jsonPath("$.warnings[1]").value(EmailExtractService.HTML_WARNING))
				.andExpect(jsonPath("$.warnings[2]").value(EmailExtractService.TRUNCATION_WARNING))
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(response).doesNotContain("https://example.com/n/21");
	}

	@Test
	void twentyUniqueUrlsAreNotTruncated() throws Exception {
		mockMvc.perform(post("/api/email/extract")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body(numberedUrls(20))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.truncated").value(false))
				.andExpect(jsonPath("$.urls.length()").value(20))
				.andExpect(jsonPath("$.warnings.length()").value(2));
	}

	@Test
	void rejectsBlankOversizedAndUnreadableText() throws Exception {
		assertInvalid("{\"text\":\"\"}");
		assertInvalid("{\"text\":\"   \"}");
		assertInvalid("{}");
		assertInvalid("{");

		String marker = "DO-NOT-ECHO-THIS-TEXT";
		String oversized = marker + "x".repeat(EmailExtractRequest.MAX_LENGTH);
		assertInvalid(body(oversized));
	}

	@Test
	void acceptsTextAtTheMaximumLength() throws Exception {
		String prefix = "https://example.com/ok ";
		String text = prefix + "a".repeat(EmailExtractRequest.MAX_LENGTH - prefix.length());

		mockMvc.perform(post("/api/email/extract")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body(text)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.urls[0]").value("https://example.com/ok"))
				.andExpect(jsonPath("$.truncated").value(false));
	}

	private void assertInvalid(String json) throws Exception {
		String response = mockMvc.perform(post("/api/email/extract")
						.contentType(MediaType.APPLICATION_JSON)
						.content(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_text"))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("DO-NOT-ECHO-THIS-TEXT");
		assertThat(response).doesNotContain("example.com");
	}

	private static String body(String text) {
		return "{\"text\":\"" + text.replace("\\", "\\\\").replace("\"", "\\\"")
				.replace("\r", "\\r").replace("\n", "\\n") + "\"}";
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
