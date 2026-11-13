package com.agguidigital.phishingchecker.web;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JsonRequestSizeFilterTest {

	private static final String MARKER = "UNIQUE-BODY-MARKER";

	@Test
	void singleByteReadsStopOneBytePastTheLimit() throws Exception {
		MeteredStream source = new MeteredStream();
		ServletInputStream bounded = JsonRequestSizeFilter.limit(source);

		assertThatThrownBy(() -> {
			int total = 0;
			while (bounded.read() >= 0) {
				total++;
				if (total > JsonRequestSizeFilter.MAX_JSON_BYTES) {
					throw new AssertionError("single-byte read returned a byte past the limit");
				}
			}
		}).isInstanceOf(IOException.class).hasMessage("request body exceeded the size limit");

		assertThat(source.bulkRequests).isEmpty();
		assertThat(source.singleReads).isEqualTo(JsonRequestSizeFilter.MAX_JSON_BYTES + 1);
	}

	@Test
	void bulkReadsAskForAtMostTheRemainingAllowancePlusOneByte() throws Exception {
		MeteredStream source = new MeteredStream();
		ServletInputStream bounded = JsonRequestSizeFilter.limit(source);
		byte[] buffer = new byte[10_000];
		List<Integer> accepted = new ArrayList<>();

		assertThatThrownBy(() -> {
			int read;
			while ((read = bounded.read(buffer)) >= 0) {
				accepted.add(read);
			}
		}).isInstanceOf(IOException.class).hasMessage("request body exceeded the size limit");

		long counted = 0;
		for (int requested : source.bulkRequests) {
			long allowance = Math.max(1L, (JsonRequestSizeFilter.MAX_JSON_BYTES - counted) + 1L);
			assertThat(requested).isBetween(1, (int) Math.min(buffer.length, allowance));
			counted += requested;
		}
		assertThat(counted).isEqualTo(JsonRequestSizeFilter.MAX_JSON_BYTES + 1L);
		assertThat(source.singleReads).isZero();
		assertThat(accepted.stream().mapToInt(Integer::intValue).sum()).isLessThan(JsonRequestSizeFilter.MAX_JSON_BYTES + 1);
	}

	@Test
	void exactLimitIsReadableInOneBulkRequest() throws Exception {
		byte[] body = new byte[JsonRequestSizeFilter.MAX_JSON_BYTES];
		Arrays.fill(body, (byte) 'a');
		ServletInputStream bounded = JsonRequestSizeFilter.limit(new FiniteStream(body));
		byte[] buffer = new byte[body.length + 100];

		int first = bounded.read(buffer);
		int second = bounded.read(buffer);

		assertThat(first).isEqualTo(body.length);
		assertThat(second).isEqualTo(-1);
	}

	@Test
	void oversizedRequestWithoutContentLengthIsRejectedWithoutEchoingIt() throws Exception {
		assertRejectedWithoutEcho(true);
		assertRejectedWithoutEcho(false);
	}

	private static void assertRejectedWithoutEcho(boolean bulk) throws Exception {
		byte[] body = new byte[JsonRequestSizeFilter.MAX_JSON_BYTES + 64];
		Arrays.fill(body, (byte) ' ');
		byte[] marker = MARKER.getBytes(StandardCharsets.UTF_8);
		System.arraycopy(marker, 0, body, 0, marker.length);
		MockHttpServletRequest request = new MockHttpServletRequest() {
			@Override
			public int getContentLength() {
				return -1;
			}

			@Override
			public long getContentLengthLong() {
				return -1L;
			}
		};
		request.setMethod("POST");
		request.setRequestURI("/api/email/analyze");
		request.setContentType("application/json");
		request.setContent(body);
		assertThat(request.getContentLengthLong()).isEqualTo(-1L);
		MockHttpServletResponse response = new MockHttpServletResponse();

		new JsonRequestSizeFilter().doFilter(request, response, (servletRequest, servletResponse) -> {
			ServletInputStream input = ((HttpServletRequest) servletRequest).getInputStream();
			if (bulk) {
				byte[] buffer = new byte[8192];
				while (input.read(buffer) >= 0) {
					// Read the wrapped stream so the limit applies without Content-Length.
				}
			}
			else {
				while (input.read() >= 0) {
					// Read one byte at a time so the single-byte path applies.
				}
			}
		});

		assertThat(response.getStatus()).isEqualTo(400);
		assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"invalid_text\"}").doesNotContain(MARKER);
	}

	private static final class MeteredStream extends ServletInputStream {

		private final List<Integer> bulkRequests = new ArrayList<>();

		private int singleReads;

		@Override
		public int read() {
			singleReads++;
			return 'x';
		}

		@Override
		public int read(byte[] buffer, int offset, int length) {
			bulkRequests.add(length);
			Arrays.fill(buffer, offset, offset + length, (byte) 'x');
			return length;
		}

		@Override
		public boolean isFinished() {
			return false;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener readListener) {
		}

	}

	private static final class FiniteStream extends ServletInputStream {

		private final ByteArrayInputStream source;

		private FiniteStream(byte[] body) {
			this.source = new ByteArrayInputStream(body);
		}

		@Override
		public int read() {
			return source.read();
		}

		@Override
		public int read(byte[] buffer, int offset, int length) {
			return source.read(buffer, offset, length);
		}

		@Override
		public boolean isFinished() {
			return source.available() == 0;
		}

		@Override
		public boolean isReady() {
			return true;
		}

		@Override
		public void setReadListener(ReadListener readListener) {
		}

	}

}
