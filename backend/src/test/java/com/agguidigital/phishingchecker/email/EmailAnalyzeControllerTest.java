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
class EmailAnalyzeControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void returnsExplainableAssessmentWithoutEchoingTheText() throws Exception {
		String marker = "DO-NOT-ECHO-THIS-TEXT";
		String text = "Reply with your password. " + marker;

		String response = mockMvc.perform(post("/api/email/analyze")
						.contentType(MediaType.APPLICATION_JSON)
						.content(body(text)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.assessment").value("suspicious"))
				.andExpect(jsonPath("$.findings[0].ruleId").value(EmailTextAnalyzer.CREDENTIAL_REQUEST))
				.andExpect(jsonPath("$.findings[0].explanation").value(EmailTextAnalyzer.CREDENTIAL_EXPLANATION))
				.andExpect(jsonPath("$.limitations[0]").value(EmailTextAnalyzer.MISSED_THREATS_LIMITATION))
				.andExpect(jsonPath("$.limitations[1]").value(EmailTextAnalyzer.SCOPE_LIMITATION))
				.andExpect(jsonPath("$.probability").doesNotExist())
				.andReturn()
				.getResponse()
				.getContentAsString();

		assertThat(response).doesNotContain(marker);
		assertThat(response).doesNotContainIgnoringCase("confirmed");
		assertThat(response).doesNotContainIgnoringCase("probability");
	}

	@Test
	void reusesTheEmailTextValidation() throws Exception {
		assertInvalid("{\"text\":\"\"}");
		assertInvalid("{\"text\":\"   \"}");
		assertInvalid("{}");
		assertInvalid("{");

		String marker = "DO-NOT-ECHO-THIS-TEXT";
		assertInvalid(body(marker + "x".repeat(EmailExtractRequest.MAX_LENGTH)));
	}

	private void assertInvalid(String json) throws Exception {
		String response = mockMvc.perform(post("/api/email/analyze")
						.contentType(MediaType.APPLICATION_JSON)
						.content(json))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_text"))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("DO-NOT-ECHO-THIS-TEXT");
	}

	private static String body(String text) {
		return "{\"text\":\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
	}

}
