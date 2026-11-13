package com.agguidigital.phishingchecker.phishtank;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

class PhishTankPropertiesTest {

	private static final String DUMMY_KEY = "pt-test-key";

	@Test
	void disabledByDefaultEvenWhenAnApplicationKeyIsPresent() {
		PhishTankProperties properties = new PhishTankProperties();

		assertThat(properties.isEnabled()).isFalse();
		assertThat(properties.getUserAgent()).isEqualTo(PhishTankClient.DEFAULT_USER_AGENT);
		properties.setAppKey(DUMMY_KEY);
		assertThat(properties.isEnabled()).isFalse();
		assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
		assertThat(properties.toString()).isEqualTo("PhishTankProperties{enabled=false}");
	}

	@Test
	void blankApplicationKeyStaysBlank() {
		PhishTankProperties properties = new PhishTankProperties();

		properties.setAppKey(null);
		assertThat(properties.getAppKey()).isEmpty();
		properties.setAppKey("   ");
		assertThat(properties.getAppKey()).isEmpty();
	}

	@Test
	void enablingDoesNotCopyTheKeyIntoToString() {
		PhishTankProperties properties = new PhishTankProperties();

		properties.setEnabled(true);
		properties.setAppKey("  " + DUMMY_KEY + "  ");
		assertThat(properties.isEnabled()).isTrue();
		assertThat(properties.getAppKey()).isEqualTo(DUMMY_KEY);
		assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
	}

	@Nested
	@SpringBootTest(properties = { "phishtank.enabled=false", "phishtank.app-key=pt-test-key", "virustotal.api-key=" })
	class DisabledWhenConfiguredOff {

		@Autowired
		private PhishTankProperties properties;

		@Test
		void keyDoesNotEnableTheIntegration() {
			assertThat(properties.isEnabled()).isFalse();
			assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
		}

	}

	@Nested
	@SpringBootTest(properties = { "phishtank.enabled=true", "phishtank.app-key=pt-test-key", "phishtank.user-agent=phishtank-test-agent", "virustotal.api-key=" })
	class EnabledOnlyByTheFlag {

		@Autowired
		private PhishTankProperties properties;

		@Test
		void flagEnablesWithoutExposingTheKey() {
			assertThat(properties.isEnabled()).isTrue();
			assertThat(properties.getUserAgent()).isEqualTo("phishtank-test-agent");
			assertThat(properties.toString()).doesNotContain(DUMMY_KEY);
		}

	}

}
