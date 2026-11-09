package com.agguidigital.phishingchecker;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class HealthControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void healthReturnsOk() throws Exception {
		mockMvc.perform(get("/api/health").accept(MediaType.APPLICATION_JSON))
				.andExpect(status().isOk())
				.andExpect(content().json("{\"status\":\"ok\"}"));
	}

}
