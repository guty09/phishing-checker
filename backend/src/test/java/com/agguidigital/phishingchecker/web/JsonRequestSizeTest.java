package com.agguidigital.phishingchecker.web;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.agguidigital.phishingchecker.email.EmailExtractRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "virustotal.api-key=")
@AutoConfigureMockMvc
class JsonRequestSizeTest {

	@Autowired
	private MockMvc mockMvc;

	@Value("${spring.jackson.factory.constraints.read.max-string-length}")
	private int maxStringLength;

	@Value("${spring.jackson.factory.constraints.read.max-document-length}")
	private int maxDocumentLength;

	@Test
	void limitsMatchTheMessageTextBudget() {
		assertThat(maxStringLength).isEqualTo(EmailExtractRequest.MAX_LENGTH);
		assertThat(maxDocumentLength).isEqualTo(JsonRequestSizeFilter.MAX_JSON_BYTES);
		assertThat(JsonRequestSizeFilter.MAX_JSON_BYTES).isGreaterThanOrEqualTo(EmailExtractRequest.MAX_LENGTH * 6 + "{\"text\":\"\"}".length());
	}

	@Test
	void acceptsTheMaximumMultibyteText() throws Exception {
		mockMvc.perform(post("/api/email/analyze")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body("é".repeat(EmailExtractRequest.MAX_LENGTH))))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.assessment").value("no_obvious_warning_signs"));
	}

	@Test
	void acceptsTheMaximumTextWhenEveryCharacterIsEscaped() throws Exception {
		String json = "{\"text\":\"" + "\\u00e9".repeat(EmailExtractRequest.MAX_LENGTH) + "\"}";
		assertThat(json.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(JsonRequestSizeFilter.MAX_JSON_BYTES);

		mockMvc.perform(post("/api/email/analyze")
						.contentType(MediaType.APPLICATION_JSON)
						.content(json))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.assessment").value("no_obvious_warning_signs"));
	}

	@Test
	void rejectsAnOversizedBodyWithoutEchoingIt() throws Exception {
		byte[] body = new byte[JsonRequestSizeFilter.MAX_JSON_BYTES + 1];
		Arrays.fill(body, (byte) ' ');
		byte[] prefix = "{\"text\":\"UNIQUE-BODY-MARKER\"".getBytes(StandardCharsets.UTF_8);
		System.arraycopy(prefix, 0, body, 0, prefix.length);

		String response = mockMvc.perform(post("/api/email/analyze")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_text"))
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(response).doesNotContain("UNIQUE-BODY-MARKER");
	}

	private static String body(String text) {
		return "{\"text\":\"" + text + "\"}";
	}

}
