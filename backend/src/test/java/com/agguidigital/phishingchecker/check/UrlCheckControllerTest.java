package com.agguidigital.phishingchecker.check;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "virustotal.api-key=")
@AutoConfigureMockMvc
class UrlCheckControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void healthStaysAvailable() throws Exception {
		mockMvc.perform(get("/api/health"))
				.andExpect(status().isOk())
				.andExpect(content().json("{\"status\":\"ok\"}"));
	}

	@Test
	void missingKeyDisablesLookupForAValidUrl() throws Exception {
		mockMvc.perform(post("/api/check/url")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"url\":\"https://example.com\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.provider").value("virustotal"))
				.andExpect(jsonPath("$.status").value("disabled"))
				.andExpect(jsonPath("$.analysis").doesNotExist());
	}

	@Test
	void invalidUrlIsRejected() throws Exception {
		String response = mockMvc.perform(post("/api/check/url")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"url\":\"ftp://example.com/not-fetched\"}"))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("invalid_url"))
				.andReturn()
				.getResponse()
				.getContentAsString();
		org.assertj.core.api.Assertions.assertThat(response).doesNotContain("not-fetched");
	}

}
