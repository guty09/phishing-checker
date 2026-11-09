package com.agguidigital.phishingchecker.virustotal;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

class VirusTotalPropertiesTest {

	private static final String DUMMY_KEY = "placeholder";

	@Test
	void missingKeyLeavesIntegrationDisabled() {
		VirusTotalProperties properties = new VirusTotalProperties();

		assertThat(properties.isEnabled()).isFalse();

		properties.setApiKey(null);
		assertThat(properties.isEnabled()).isFalse();
		assertThat(properties.toString()).doesNotContain("apiKey");
	}

	@Test
	void blankKeyLeavesIntegrationDisabled() {
		VirusTotalProperties properties = new VirusTotalProperties();

		properties.setApiKey("");
		assertThat(properties.isEnabled()).isFalse();

		properties.setApiKey("   ");
		assertThat(properties.isEnabled()).isFalse();
	}

	@Test
	void dummyKeyEnablesIntegrationWithoutExposingIt() {
		VirusTotalProperties properties = new VirusTotalProperties();

		properties.setApiKey(DUMMY_KEY);
		assertThat(properties.isEnabled()).isTrue();
		assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
	}

	@Nested
	@SpringBootTest(properties = "virustotal.api-key=")
	class DisabledWhenKeyIsBlank {

		@Autowired
		private VirusTotalProperties properties;

		@Test
		void integrationIsDisabled() {
			assertThat(properties.isEnabled()).isFalse();
			assertThat(properties.toString()).doesNotContain("apiKey");
		}

	}

	@Nested
	@SpringBootTest(properties = "virustotal.api-key=placeholder")
	class EnabledWhenKeyIsPresent {

		@Autowired
		private VirusTotalProperties properties;

		@Test
		void integrationIsEnabledWithoutExposingTheKey() {
			assertThat(properties.isEnabled()).isTrue();
			assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
		}

	}

}
