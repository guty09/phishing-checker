package com.agguidigital.phishingchecker.phishtank;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.time.Duration;

import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.Test;

import com.agguidigital.phishingchecker.check.PhishTankDiagnostic;
import com.agguidigital.phishingchecker.check.PhishTankStatus;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PhishTankClientTest {

	@Test
	void doesNotContactAnUnpinnedHost() throws Exception {
		try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			socket.setSoTimeout(300);
			URI endpoint = URI.create("https://127.0.0.1:" + socket.getLocalPort() + "/checkurl/");
			HttpClient httpClient = HttpClient.newBuilder()
					.connectTimeout(Duration.ofMillis(200))
					.followRedirects(HttpClient.Redirect.NEVER)
					.build();
			PhishTankClient client = new PhishTankClient(httpClient, endpoint, Duration.ofMillis(200), 128);

			PhishTankOutcome outcome = client.lookup("https://example.com/UNIQUE-URL-MARKER", "pt-test-key", "phishing-checker test");

			assertThat(outcome.status()).isEqualTo(PhishTankStatus.unavailable);
			assertThat(outcome.toString()).doesNotContain("pt-test-key").doesNotContain("UNIQUE-URL-MARKER");
			assertThatThrownBy(socket::accept).isInstanceOf(SocketTimeoutException.class);
		}
	}

	@Test
	void connectionRefusalIsAConnectionFailureWithoutTheExceptionText() throws Exception {
		int port;
		try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
			port = socket.getLocalPort();
		}
		HttpClient httpClient = HttpClient.newBuilder()
				.connectTimeout(Duration.ofSeconds(2))
				.followRedirects(HttpClient.Redirect.NEVER)
				.build();
		PhishTankClient client = new PhishTankClient(httpClient, URI.create("http://127.0.0.1:" + port + "/checkurl/"), Duration.ofSeconds(2), 128);

		PhishTankOutcome outcome = client.lookup("https://example.com/UNIQUE-URL-MARKER", "pt-test-key", "phishing-checker test");

		assertThat(outcome.status()).isEqualTo(PhishTankStatus.unavailable);
		assertThat(outcome.diagnostic()).isEqualTo(PhishTankDiagnostic.connection_failure);
		assertThat(outcome.providerStatus()).isNull();
		assertThat(outcome.toString()).doesNotContain("pt-test-key").doesNotContain("UNIQUE-URL-MARKER").doesNotContain("Connection refused");
	}

	@Test
	void transportDiagnosticsUseCategoriesRatherThanExceptionText() {
		assertThat(PhishTankClient.transportDiagnostic(new HttpTimeoutException("timed out contacting https://user:secret@example.com/path")))
				.isEqualTo(PhishTankDiagnostic.timeout);
		assertThat(PhishTankClient.transportDiagnostic(new SSLHandshakeException("handshake failed for secret-key")))
				.isEqualTo(PhishTankDiagnostic.connection_failure);
		assertThat(PhishTankClient.transportDiagnostic(new IOException("response exceeded the size limit")))
				.isEqualTo(PhishTankDiagnostic.connection_failure);
		assertThat(PhishTankDiagnostic.timeout.toString()).doesNotContain("secret");
	}

}
