package com.agguidigital.phishingchecker.web;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.agguidigital.phishingchecker.email.EmailExtractRequest;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Bounds JSON request bodies without logging them.
 * A 50,000-character value encoded entirely as six-character unicode escapes is 300,000 bytes,
 * plus the small JSON envelope. {@link #MAX_JSON_BYTES} accepts that encoding and ordinary
 * multibyte UTF-8. Each underlying read asks for at most the remaining allowance plus one byte,
 * including when Content-Length is absent. Jackson's decoded string limit remains
 * {@link EmailExtractRequest#MAX_LENGTH}.
 */
@Component
public class JsonRequestSizeFilter extends OncePerRequestFilter {

	public static final int MAX_JSON_BYTES = 524_288;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!limitsJsonBody(request)) {
			filterChain.doFilter(request, response);
			return;
		}
		if (request.getContentLengthLong() > MAX_JSON_BYTES) {
			reject(request, response);
			return;
		}
		try {
			filterChain.doFilter(new BoundedJsonRequest(request), response);
		}
		catch (Exception ex) {
			if (!response.isCommitted() && causedBySizeLimit(ex)) {
				reject(request, response);
				return;
			}
			if (ex instanceof ServletException servletException) {
				throw servletException;
			}
			if (ex instanceof IOException ioException) {
				throw ioException;
			}
			if (ex instanceof RuntimeException runtimeException) {
				throw runtimeException;
			}
			throw new ServletException(ex);
		}
	}

	static boolean limitsJsonBody(HttpServletRequest request) {
		if (!"POST".equalsIgnoreCase(request.getMethod())) {
			return false;
		}
		String type = request.getContentType();
		return type != null && type.toLowerCase(Locale.ROOT).startsWith("application/json");
	}

	private static boolean causedBySizeLimit(Throwable failure) {
		Throwable current = failure;
		while (current != null) {
			if (current instanceof RequestBodyTooLargeException) {
				return true;
			}
			current = current.getCause();
		}
		return false;
	}

	private static void reject(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String path = request.getRequestURI();
		String code = path != null && path.startsWith("/api/email/") ? "invalid_text" : "invalid_url";
		response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
		response.setContentType("application/json");
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.getWriter().write("{\"error\":\"" + code + "\"}");
	}

	private static final class RequestBodyTooLargeException extends IOException {

		RequestBodyTooLargeException() {
			super("request body exceeded the size limit");
		}

	}

	private static final class BoundedJsonRequest extends HttpServletRequestWrapper {

		private final ServletInputStream stream;

		BoundedJsonRequest(HttpServletRequest request) throws IOException {
			super(request);
			this.stream = limit(request.getInputStream());
		}

		@Override
		public ServletInputStream getInputStream() {
			return stream;
		}

		@Override
		public BufferedReader getReader() {
			return new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));
		}

	}

	static ServletInputStream limit(ServletInputStream delegate) {
		return new BoundedStream(delegate);
	}

	private static final class BoundedStream extends ServletInputStream {

		private final ServletInputStream delegate;

		private long count;

		BoundedStream(ServletInputStream delegate) {
			this.delegate = delegate;
		}

		@Override
		public int read() throws IOException {
			int next = delegate.read();
			if (next >= 0) {
				count++;
				if (count > MAX_JSON_BYTES) {
					throw new RequestBodyTooLargeException();
				}
			}
			return next;
		}

		@Override
		public int read(byte[] buffer, int offset, int length) throws IOException {
			if (length <= 0) {
				return 0;
			}
			int allowed = (int) Math.min(length, Math.max(1L, (MAX_JSON_BYTES - count) + 1L));
			int read = delegate.read(buffer, offset, allowed);
			if (read > 0) {
				count += read;
				if (count > MAX_JSON_BYTES) {
					throw new RequestBodyTooLargeException();
				}
			}
			return read;
		}

		@Override
		public boolean isFinished() {
			return delegate.isFinished();
		}

		@Override
		public boolean isReady() {
			return delegate.isReady();
		}

		@Override
		public void setReadListener(ReadListener readListener) {
			delegate.setReadListener(readListener);
		}

	}

}
