package com.agguidigital.phishingchecker.check;

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

@SpringBootTest(properties = { "virustotal.api-key=", "phishtank.enabled=false", "phishtank.app-key=pt-test-key" })
@AutoConfigureMockMvc
class PhishTankWiringTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void phishTankStaysDisabledWithoutChangingVirusTotal() throws Exception {
		String response = mockMvc.perform(post("/api/check/url/phishtank")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"url\":\"https://example.com\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.provider").value("phishtank"))
				.andExpect(jsonPath("$.status").value("disabled"))
				.andExpect(jsonPath("$.limitations[0]").value("Not listed does not mean the URL is safe."))
				.andReturn()
				.getResponse()
				.getContentAsString();
		assertThat(response).doesNotContain("pt-test-key");

		mockMvc.perform(post("/api/check/url")
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"url\":\"https://example.com\"}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.provider").value("virustotal"))
				.andExpect(jsonPath("$.status").value("disabled"));
	}

}
